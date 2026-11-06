use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Utc};
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use serde::Serialize;
use serde_json::json;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

use crate::audit::Actor;
use crate::identity::orgs::record;
use crate::platform::authz::{self, Permission};
use crate::platform::error::{ServiceError, ServiceResult, conflict, invalid, unique_violation};
use crate::platform::mail::DkimKey;
use crate::platform::secrets::Secrets;

const MAX_DOMAINS: i64 = 20;

#[derive(Debug, Clone, Serialize)]
pub struct DnsRecord {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MailDomain {
    pub id: Uuid,
    pub domain: String,
    pub verified: bool,
    pub verified_at: Option<DateTime<Utc>>,
    pub last_checked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub dns_record: DnsRecord,
}

type DomainRow = (
    Uuid,
    String,
    String,
    String,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    DateTime<Utc>,
);

macro_rules! domain_columns {
    () => {
        "id, domain, selector, dkim_public_key, verified_at, last_checked_at, created_at"
    };
}

fn record_value(public_key: &str) -> String {
    format!("v=DKIM1; k=rsa; p={public_key}")
}

fn domain_from(row: DomainRow) -> MailDomain {
    let (id, domain, selector, public_key, verified_at, last_checked_at, created_at) = row;
    MailDomain {
        id,
        dns_record: DnsRecord {
            name: format!("{selector}._domainkey.{domain}"),
            kind: "TXT",
            value: record_value(&public_key),
        },
        domain,
        verified: verified_at.is_some(),
        verified_at,
        last_checked_at,
        created_at,
    }
}

fn key_context(id: Uuid) -> String {
    format!("mail_domain:{id}:dkim")
}

pub fn normalize_domain(value: &str) -> ServiceResult<String> {
    let domain = value.trim().trim_end_matches('.').to_ascii_lowercase();
    let label_ok = |l: &str| {
        (1..=63).contains(&l.len())
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    let labels: Vec<&str> = domain.split('.').collect();
    if domain.len() > 253
        || labels.len() < 2
        || !labels.iter().all(|l| label_ok(l))
        || labels
            .last()
            .is_some_and(|tld| tld.chars().all(|c| c.is_ascii_digit()))
    {
        return Err(invalid("domain", "is not a valid domain name"));
    }
    Ok(domain)
}

pub async fn list(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
) -> ServiceResult<Vec<MailDomain>> {
    authz::require(conn, org_id, actor, Permission::OrganizationManage).await?;
    let rows: Vec<DomainRow> = sqlx::query_as(concat!(
        "SELECT ",
        domain_columns!(),
        " FROM mail_domains WHERE org_id = $1 ORDER BY domain"
    ))
    .bind(org_id)
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().map(domain_from).collect())
}

async fn load(conn: &mut PgConnection, org_id: Uuid, id: Uuid) -> ServiceResult<MailDomain> {
    let row: DomainRow = sqlx::query_as(concat!(
        "SELECT ",
        domain_columns!(),
        " FROM mail_domains WHERE org_id = $1 AND id = $2"
    ))
    .bind(org_id)
    .bind(id)
    .fetch_optional(conn)
    .await?
    .ok_or(ServiceError::NotFound)?;
    Ok(domain_from(row))
}

pub async fn add(
    conn: &mut PgConnection,
    secrets: &Secrets,
    org_id: Uuid,
    actor: Actor,
    domain: &str,
) -> ServiceResult<MailDomain> {
    let domain = normalize_domain(domain)?;
    let rsa = Rsa::generate(2048).map_err(anyhow::Error::from)?;
    let private_pem = rsa.private_key_to_pem().map_err(anyhow::Error::from)?;
    let public_der = PKey::from_rsa(rsa)
        .and_then(|k| k.public_key_to_der())
        .map_err(anyhow::Error::from)?;
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::OrganizationManage).await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM mail_domains WHERE org_id = $1")
        .bind(org_id)
        .fetch_one(&mut *tx)
        .await?;
    if count >= MAX_DOMAINS {
        return Err(invalid(
            "domain",
            "the organization has the maximum number of sending domains",
        ));
    }
    let id = Uuid::now_v7();
    let selector = format!("ultrivly-{}", &id.simple().to_string()[24..]);
    sqlx::query(
        "INSERT INTO mail_domains (id, org_id, domain, selector, dkim_private_key_ciphertext, dkim_public_key)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(org_id)
    .bind(&domain)
    .bind(&selector)
    .bind(secrets.encrypt(&key_context(id), &private_pem))
    .bind(STANDARD.encode(public_der))
    .execute(&mut *tx)
    .await
    .map_err(|err| {
        if unique_violation(&err, "mail_domains_org_id_domain_key") {
            conflict("domain_exists", "this domain is already added")
        } else {
            err.into()
        }
    })?;
    record(
        &mut tx,
        org_id,
        actor,
        "mail_domain.added",
        "mail_domain",
        id,
        json!({ "domain": domain }),
    )
    .await?;
    let added = load(&mut tx, org_id, id).await?;
    tx.commit().await?;
    Ok(added)
}

pub fn record_matches(records: &[String], expected_public_key: &str) -> bool {
    records.iter().any(|record| {
        let compact: String = record.chars().filter(|c| !c.is_whitespace()).collect();
        compact
            .split(';')
            .filter_map(|tag| tag.split_once('='))
            .any(|(name, value)| name == "p" && value == expected_public_key)
    })
}

pub async fn lookup_txt(name: &str) -> anyhow::Result<Vec<String>> {
    let resolver = hickory_resolver::TokioResolver::builder_tokio()?.build()?;
    let lookup = match resolver.txt_lookup(name).await {
        Ok(lookup) => lookup,
        Err(err) if err.is_no_records_found() => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };
    Ok(lookup
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            hickory_resolver::proto::rr::RData::TXT(txt) => Some(
                txt.txt_data
                    .iter()
                    .map(|part| String::from_utf8_lossy(part).into_owned())
                    .collect::<String>(),
            ),
            _ => None,
        })
        .collect())
}

pub async fn verify(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    id: Uuid,
    records: &[String],
) -> ServiceResult<MailDomain> {
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::OrganizationManage).await?;
    let public_key: String = sqlx::query_scalar(
        "SELECT dkim_public_key FROM mail_domains WHERE org_id = $1 AND id = $2 FOR UPDATE",
    )
    .bind(org_id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ServiceError::NotFound)?;
    let found = record_matches(records, &public_key);
    sqlx::query(
        "UPDATE mail_domains SET last_checked_at = now(),
                verified_at = CASE WHEN $3 THEN coalesce(verified_at, now()) ELSE NULL END
         WHERE org_id = $1 AND id = $2",
    )
    .bind(org_id)
    .bind(id)
    .bind(found)
    .execute(&mut *tx)
    .await?;
    record(
        &mut tx,
        org_id,
        actor,
        "mail_domain.checked",
        "mail_domain",
        id,
        json!({ "verified": found }),
    )
    .await?;
    let checked = load(&mut tx, org_id, id).await?;
    tx.commit().await?;
    Ok(checked)
}

pub async fn dns_name(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    id: Uuid,
) -> ServiceResult<String> {
    authz::require(conn, org_id, actor, Permission::OrganizationManage).await?;
    Ok(load(conn, org_id, id).await?.dns_record.name)
}

pub async fn remove(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    id: Uuid,
) -> ServiceResult<()> {
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::OrganizationManage).await?;
    let domain: String = sqlx::query_scalar(
        "DELETE FROM mail_domains WHERE org_id = $1 AND id = $2 RETURNING domain",
    )
    .bind(org_id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ServiceError::NotFound)?;
    record(
        &mut tx,
        org_id,
        actor,
        "mail_domain.removed",
        "mail_domain",
        id,
        json!({ "domain": domain }),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn signing_key(
    conn: &mut PgConnection,
    secrets: &Secrets,
    org_id: Uuid,
    address: &str,
) -> anyhow::Result<Option<DkimKey>> {
    let Some((_, domain)) = address.rsplit_once('@') else {
        return Ok(None);
    };
    let row: Option<(Uuid, String, String, Vec<u8>)> = sqlx::query_as(
        "SELECT id, domain, selector, dkim_private_key_ciphertext FROM mail_domains
         WHERE org_id = $1 AND domain = lower($2) AND verified_at IS NOT NULL",
    )
    .bind(org_id)
    .bind(domain)
    .fetch_optional(conn)
    .await?;
    let Some((id, domain, selector, ciphertext)) = row else {
        return Ok(None);
    };
    Ok(Some(DkimKey {
        domain,
        selector,
        private_key_pem: String::from_utf8(secrets.decrypt(&key_context(id), &ciphertext)?)?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_validated() {
        assert_eq!(
            normalize_domain(" Mail.Example.COM. ").unwrap(),
            "mail.example.com"
        );
        for bad in [
            "localhost",
            "1.2.3.4",
            "-a.com",
            "a..com",
            "exa mple.com",
            "a.com/x",
        ] {
            assert!(normalize_domain(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn dns_record_must_carry_our_key() {
        assert!(record_matches(&["v=DKIM1; k=rsa; p=ABC".into()], "ABC"));
        assert!(record_matches(&["v=DKIM1;k=rsa;p=AB C".into()], "ABC"));
        assert!(!record_matches(&["v=DKIM1; k=rsa; p=ABCD".into()], "ABC"));
        assert!(!record_matches(&["v=DKIM1; k=rsa; p=XYZ".into()], "ABC"));
    }
}
