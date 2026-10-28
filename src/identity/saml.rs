use std::str::FromStr;
use std::time::Duration;

use samael::crypto::AllowedSignatureAlgorithm;
use samael::metadata::{EntityDescriptor, HTTP_REDIRECT_BINDING};
use samael::schema::Assertion;
use samael::service_provider::{ServiceProvider, ServiceProviderBuilder};
use samael::traits::ToXml;
use serde_json::json;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

use crate::audit::Actor;
use crate::identity::sessions::ClientInfo;
use crate::identity::sso::{
    Identity, ProviderConfig, ProviderKind, Sso, SsoError, SsoOutcome, check_default_role,
    is_safe_redirect, normalize_domains, record_org,
};
use crate::platform::authz::{self, Permission};
use crate::platform::secrets::random_bytes;

const REQUEST_TTL: Duration = Duration::from_secs(10 * 60);

const EMAIL_ATTRIBUTES: &[&str] = &[
    "email",
    "mail",
    "emailaddress",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "urn:oid:0.9.2342.19200300.100.1.3",
];

const NAME_ATTRIBUTES: &[&str] = &[
    "displayname",
    "name",
    "http://schemas.microsoft.com/identity/claims/displayname",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
    "urn:oid:2.16.840.1.113730.3.1.241",
];

pub struct NewSamlConnection<'a> {
    pub name: &'a str,
    pub idp_metadata_xml: &'a str,
    pub email_domains: &'a [&'a str],
    pub jit_provisioning: bool,
    pub default_role_id: Option<Uuid>,
    pub enforced: bool,
}

struct SamlConnection {
    org_id: Uuid,
    metadata: EntityDescriptor,
    email_domains: Vec<String>,
    jit_provisioning: bool,
    default_role_id: Option<Uuid>,
}

impl Sso {
    pub fn saml_entity_id(&self, connection_id: Uuid) -> String {
        format!("{}/auth/saml/{connection_id}/metadata", self.public_url)
    }

    pub fn saml_acs_url(&self, connection_id: Uuid) -> String {
        format!("{}/auth/saml/{connection_id}/acs", self.public_url)
    }

    pub async fn create_saml_connection(
        &self,
        conn: &mut PgConnection,
        org_id: Uuid,
        actor: Actor,
        new: NewSamlConnection<'_>,
    ) -> Result<Uuid, SsoError> {
        authz::require(conn, org_id, actor, Permission::SecurityManage).await?;
        let name = new.name.trim();
        if name.is_empty() || name.chars().count() > 100 {
            return Err(SsoError::Invalid {
                field: "name",
                reason: "must be between 1 and 100 characters",
            });
        }
        let email_domains = normalize_domains(new.email_domains)?;
        let id = Uuid::now_v7();
        let metadata = parse_metadata(new.idp_metadata_xml)?;
        self.validate_idp(id, &metadata)?;

        let mut tx = conn.begin().await?;
        if let Some(role_id) = new.default_role_id {
            check_default_role(&mut tx, org_id, actor, role_id).await?;
        }
        sqlx::query(
            "INSERT INTO sso_connections (id, org_id, name, protocol, idp_metadata_xml, email_domains,
                 enforced, jit_provisioning, default_role_id)
             VALUES ($1, $2, $3, 'saml', $4, $5, $6, $7, $8)",
        )
        .bind(id)
        .bind(org_id)
        .bind(name)
        .bind(new.idp_metadata_xml)
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
                "protocol": "saml",
                "idp_entity_id": metadata.entity_id,
                "email_domains": email_domains,
                "enforced": new.enforced,
                "jit_provisioning": new.jit_provisioning,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    pub async fn replace_saml_metadata(
        &self,
        conn: &mut PgConnection,
        org_id: Uuid,
        connection_id: Uuid,
        actor: Actor,
        idp_metadata_xml: &str,
    ) -> Result<(), SsoError> {
        authz::require(conn, org_id, actor, Permission::SecurityManage).await?;
        let metadata = parse_metadata(idp_metadata_xml)?;
        self.validate_idp(connection_id, &metadata)?;
        let mut tx = conn.begin().await?;
        let updated = sqlx::query(
            "UPDATE sso_connections SET idp_metadata_xml = $3
             WHERE org_id = $1 AND id = $2 AND protocol = 'saml'",
        )
        .bind(org_id)
        .bind(connection_id)
        .bind(idp_metadata_xml)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if updated == 0 {
            return Err(SsoError::NotFound);
        }
        record_org(
            &mut tx,
            org_id,
            actor,
            "sso_connection.updated",
            connection_id,
            json!({ "idp_metadata_replaced": true, "idp_entity_id": metadata.entity_id }),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn saml_sp_metadata(
        &self,
        conn: &mut PgConnection,
        connection_id: Uuid,
    ) -> Result<String, SsoError> {
        let connection = self.load_saml(conn, connection_id).await?;
        let sp = self.service_provider(connection_id, connection.metadata)?;
        let descriptor = sp
            .metadata()
            .map_err(|e| SsoError::Internal(anyhow::anyhow!("building SP metadata: {e}")))?;
        descriptor
            .to_string()
            .map_err(|e| SsoError::Internal(anyhow::anyhow!("serializing SP metadata: {e}")))
    }

    pub async fn begin_saml(
        &self,
        conn: &mut PgConnection,
        connection_id: Uuid,
        redirect_to: Option<&str>,
        link_user_id: Option<Uuid>,
    ) -> Result<(String, String), SsoError> {
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
        let connection = self.load_saml(conn, connection_id).await?;
        let sp = self.service_provider(connection_id, connection.metadata)?;
        let sso_url = sp
            .sso_binding_location(HTTP_REDIRECT_BINDING)
            .ok_or(SsoError::Unavailable)?;
        let mut request = sp
            .make_authentication_request(&sso_url)
            .map_err(|e| SsoError::Internal(anyhow::anyhow!("building SAML request: {e}")))?;
        let request_id = format!("_{}", hex(&random_bytes::<32>()));
        request.id = request_id.clone();
        let url = request
            .redirect("")
            .map_err(|e| SsoError::Internal(anyhow::anyhow!("encoding SAML request: {e}")))?
            .ok_or(SsoError::Unavailable)?;

        sqlx::query(
            "INSERT INTO saml_requests (id, sso_connection_id, link_user_id, redirect_to, expires_at)
             VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))",
        )
        .bind(&request_id)
        .bind(connection_id)
        .bind(link_user_id)
        .bind(redirect_to)
        .bind(REQUEST_TTL.as_secs_f64())
        .execute(&mut *conn)
        .await?;
        Ok((url.to_string(), request_id))
    }

    pub async fn complete_saml(
        &self,
        conn: &mut PgConnection,
        connection_id: Uuid,
        saml_response: &str,
        request_id: &str,
        client_info: &ClientInfo,
    ) -> Result<SsoOutcome, SsoError> {
        let pending: Option<(Option<Uuid>, Option<String>)> = sqlx::query_as(
            "DELETE FROM saml_requests
             WHERE id = $1 AND sso_connection_id = $2 AND expires_at > now()
             RETURNING link_user_id, redirect_to",
        )
        .bind(request_id)
        .bind(connection_id)
        .fetch_optional(&mut *conn)
        .await?;
        let (link_user_id, redirect_to) = pending.ok_or(SsoError::InvalidState)?;

        let connection = self.load_saml(conn, connection_id).await?;
        let idp_entity_id = connection
            .metadata
            .entity_id
            .clone()
            .ok_or(SsoError::Unavailable)?;
        let sp = self.service_provider(connection_id, connection.metadata)?;
        let entity_id = self.saml_entity_id(connection_id);
        let response = saml_response.to_string();
        let expected = request_id.to_string();
        let assertion = tokio::task::spawn_blocking(move || {
            sp.parse_base64_response(&response, Some(&[expected.as_str()]))
                .map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| SsoError::Internal(e.into()))?
        .map_err(|e| SsoError::Provider(format!("SAML response rejected: {e}")))?;

        if !audience_matches(&assertion, &entity_id) {
            return Err(SsoError::Provider(
                "SAML assertion is not addressed to this service".into(),
            ));
        }
        let expires_at = assertion
            .conditions
            .as_ref()
            .and_then(|c| c.not_on_or_after)
            .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::hours(1));
        let first_use = sqlx::query(
            "INSERT INTO saml_assertions_used (sso_connection_id, assertion_id, expires_at)
             VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(connection_id)
        .bind(&assertion.id)
        .bind(expires_at)
        .execute(&mut *conn)
        .await?
        .rows_affected();
        if first_use == 0 {
            return Err(SsoError::Provider("SAML assertion was already used".into()));
        }

        let identity = identity_from(&assertion, idp_entity_id)?;
        let config = ProviderConfig {
            oidc: None,
            kind: ProviderKind::Connection {
                id: connection_id,
                org_id: connection.org_id,
                email_domains: connection.email_domains,
                jit_provisioning: connection.jit_provisioning,
                default_role_id: connection.default_role_id,
            },
        };
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

    async fn load_saml(
        &self,
        conn: &mut PgConnection,
        connection_id: Uuid,
    ) -> Result<SamlConnection, SsoError> {
        type Row = (Uuid, String, Vec<String>, bool, Option<Uuid>);
        let row: Option<Row> = sqlx::query_as(
            "SELECT c.org_id, c.idp_metadata_xml, c.email_domains, c.jit_provisioning, c.default_role_id
             FROM sso_connections c
             JOIN organizations o ON o.id = c.org_id AND o.deleted_at IS NULL
             WHERE c.id = $1 AND c.enabled AND c.protocol = 'saml'",
        )
        .bind(connection_id)
        .fetch_optional(conn)
        .await?;
        let (org_id, xml, email_domains, jit_provisioning, default_role_id) =
            row.ok_or(SsoError::Unavailable)?;
        Ok(SamlConnection {
            org_id,
            metadata: parse_metadata(&xml)?,
            email_domains,
            jit_provisioning,
            default_role_id,
        })
    }

    fn service_provider(
        &self,
        connection_id: Uuid,
        metadata: EntityDescriptor,
    ) -> Result<ServiceProvider, SsoError> {
        ServiceProviderBuilder::default()
            .entity_id(self.saml_entity_id(connection_id))
            .metadata_url(self.saml_entity_id(connection_id))
            .acs_url(self.saml_acs_url(connection_id))
            .slo_url(format!("{}/auth/saml/{connection_id}/slo", self.public_url))
            .idp_metadata(metadata)
            .allow_idp_initiated(false)
            .allowed_signature_algorithms(vec![
                AllowedSignatureAlgorithm::RsaSha256,
                AllowedSignatureAlgorithm::RsaSha384,
                AllowedSignatureAlgorithm::RsaSha512,
                AllowedSignatureAlgorithm::EcdsaSha256,
                AllowedSignatureAlgorithm::EcdsaSha384,
                AllowedSignatureAlgorithm::EcdsaSha512,
            ])
            .build()
            .map_err(|e| SsoError::Internal(anyhow::anyhow!("configuring SAML: {e}")))
    }

    fn validate_idp(
        &self,
        connection_id: Uuid,
        metadata: &EntityDescriptor,
    ) -> Result<(), SsoError> {
        let invalid = |reason| SsoError::Invalid {
            field: "idp_metadata_xml",
            reason,
        };
        if metadata
            .entity_id
            .as_deref()
            .is_none_or(|e| e.trim().is_empty())
        {
            return Err(invalid("must include the identity provider's entityID"));
        }
        let sp = self.service_provider(connection_id, metadata.clone())?;
        let signing_certs = sp
            .idp_signing_certs()
            .map_err(|_| invalid("contains an unreadable signing certificate"))?;
        if signing_certs.is_none_or(|certs| certs.is_empty()) {
            return Err(invalid("must include a signing certificate"));
        }
        let sso_url = sp
            .sso_binding_location(HTTP_REDIRECT_BINDING)
            .ok_or(invalid(
                "must offer single sign-on over the HTTP-Redirect binding",
            ))?;
        let sso_url =
            url::Url::parse(&sso_url).map_err(|_| invalid("has an invalid sign-on URL"))?;
        let trusted = sso_url
            .host_str()
            .is_some_and(|host| self.http.policy().is_trusted(host));
        if sso_url.scheme() != "https" && !trusted {
            return Err(invalid("must use an https sign-on URL"));
        }
        Ok(())
    }
}

fn parse_metadata(xml: &str) -> Result<EntityDescriptor, SsoError> {
    if xml.len() > 256 * 1024 {
        return Err(SsoError::Invalid {
            field: "idp_metadata_xml",
            reason: "is too large",
        });
    }
    EntityDescriptor::from_str(xml).map_err(|_| SsoError::Invalid {
        field: "idp_metadata_xml",
        reason: "is not valid SAML metadata",
    })
}

fn audience_matches(assertion: &Assertion, entity_id: &str) -> bool {
    assertion
        .conditions
        .as_ref()
        .and_then(|c| c.audience_restrictions.as_ref())
        .is_some_and(|restrictions| {
            !restrictions.is_empty()
                && restrictions
                    .iter()
                    .all(|r| r.audience.iter().any(|a| a == entity_id))
        })
}

fn identity_from(assertion: &Assertion, issuer: String) -> Result<Identity, SsoError> {
    let name_id = assertion
        .subject
        .as_ref()
        .and_then(|s| s.name_id.as_ref())
        .filter(|n| !n.value.trim().is_empty())
        .ok_or_else(|| SsoError::Provider("SAML assertion has no subject".into()))?;
    let email_from_name_id = name_id
        .format
        .as_deref()
        .is_some_and(|f| f.ends_with(":emailAddress"))
        .then(|| name_id.value.trim().to_string());
    let email = email_from_name_id.or_else(|| attribute(assertion, EMAIL_ATTRIBUTES));
    Ok(Identity {
        issuer,
        subject: name_id.value.trim().to_string(),
        email,
        email_verified: false,
        name: attribute(assertion, NAME_ATTRIBUTES),
    })
}

fn attribute(assertion: &Assertion, names: &[&str]) -> Option<String> {
    assertion
        .attribute_statements
        .iter()
        .flatten()
        .flat_map(|statement| statement.attributes.iter())
        .find(|a| {
            [a.name.as_deref(), a.friendly_name.as_deref()]
                .into_iter()
                .flatten()
                .any(|n| names.iter().any(|wanted| n.eq_ignore_ascii_case(wanted)))
        })
        .and_then(|a| a.values.iter().find_map(|v| v.value.clone()))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
