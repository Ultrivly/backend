use std::sync::{Arc, Mutex};

use anyhow::{Context, bail};
use lettre::address::Envelope;
use lettre::message::header::HeaderName;
use lettre::message::{
    DkimCanonicalization, DkimCanonicalizationType, DkimConfig, DkimSigningAlgorithm,
    DkimSigningKey, Mailbox,
};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use sqlx::PgPool;

use crate::config::Deployment;

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Email {
    pub to: String,
    pub subject: String,

    pub body: String,
    #[serde(default)]
    pub message_id: Option<String>,
    #[serde(default)]
    pub in_reply_to: Option<String>,
    #[serde(default)]
    pub reply_to: Option<String>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub bypass_suppression: bool,
    #[serde(skip)]
    pub dkim: Option<DkimKey>,
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct DkimKey {
    pub domain: String,
    pub selector: String,
    pub private_key_pem: String,
}

impl std::fmt::Debug for DkimKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DkimKey")
            .field("domain", &self.domain)
            .field("selector", &self.selector)
            .finish_non_exhaustive()
    }
}

pub async fn is_suppressed(pool: &PgPool, address: &str) -> sqlx::Result<bool> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM email_suppressions WHERE email = lower($1))")
        .bind(address.trim())
        .fetch_one(pool)
        .await
}

pub async fn send_checked(pool: &PgPool, mailer: &Mailer, email: &Email) -> anyhow::Result<bool> {
    if !email.bypass_suppression && is_suppressed(pool, &email.to).await? {
        metrics::counter!("ultrivly_emails_suppressed_total").increment(1);
        tracing::info!("skipping email to a suppressed address");
        return Ok(false);
    }
    mailer.send(email).await?;
    Ok(true)
}

#[derive(Clone)]
pub enum Mailer {
    Smtp {
        transport: Box<AsyncSmtpTransport<Tokio1Executor>>,
        from: Mailbox,
    },

    Log,

    Memory(Arc<Mutex<Vec<Email>>>),
}

impl Mailer {
    pub fn from_url(url: &str, from: &str, deployment: Deployment) -> anyhow::Result<Self> {
        if url == "log://" {
            if deployment == Deployment::Cloud {
                bail!(
                    "the log:// mailer prints sign-in links and is not allowed on Ultrivly cloud"
                );
            }
            tracing::warn!("emails will be written to the log; do not use log:// in production");
            return Ok(Mailer::Log);
        }
        if !url.starts_with("smtp://") && !url.starts_with("smtps://") {
            bail!("ULTRIVLY_MAIL_URL must start with smtps://, smtp://, or be log://");
        }
        let transport = AsyncSmtpTransport::<Tokio1Executor>::from_url(url)
            .context("invalid ULTRIVLY_MAIL_URL")?
            .build();
        let from = from.parse().context("invalid ULTRIVLY_MAIL_FROM address")?;
        Ok(Mailer::Smtp {
            transport: Box::new(transport),
            from,
        })
    }

    pub fn memory() -> (Self, Arc<Mutex<Vec<Email>>>) {
        let outbox = Arc::new(Mutex::new(Vec::new()));
        (Mailer::Memory(outbox.clone()), outbox)
    }

    pub async fn send(&self, email: &Email) -> anyhow::Result<()> {
        match self {
            Mailer::Smtp { transport, from } => {
                let to: Mailbox = email.to.parse().context("invalid recipient address")?;
                let header_from: Mailbox = match &email.from {
                    Some(address) => address.parse().context("invalid from address")?,
                    None => from.clone(),
                };
                let mut builder = Message::builder()
                    .from(header_from)
                    .to(to.clone())
                    .envelope(Envelope::new(Some(from.email.clone()), vec![to.email])?);
                if let Some(id) = &email.message_id {
                    builder = builder.message_id(Some(id.clone()));
                }
                if let Some(id) = &email.in_reply_to {
                    builder = builder.in_reply_to(id.clone()).references(id.clone());
                }
                if let Some(address) = &email.reply_to {
                    builder =
                        builder.reply_to(address.parse().context("invalid reply-to address")?);
                }
                let mut message = builder
                    .subject(email.subject.replace(['\r', '\n'], " "))
                    .body(email.body.clone())?;
                if let Some(key) = &email.dkim {
                    message.sign(&dkim_config(key, email)?);
                }
                transport
                    .send(message)
                    .await
                    .context("SMTP delivery failed")?;
            }
            Mailer::Log => {
                tracing::info!(to = %email.to, subject = %email.subject, "email (log mailer):\n{}", email.body);
            }
            Mailer::Memory(outbox) => outbox.lock().expect("outbox lock").push(email.clone()),
        }
        Ok(())
    }
}

fn dkim_config(key: &DkimKey, email: &Email) -> anyhow::Result<DkimConfig> {
    let signing_key = DkimSigningKey::new(&key.private_key_pem, DkimSigningAlgorithm::Rsa)
        .map_err(|err| anyhow::anyhow!("invalid DKIM key: {err:?}"))?;
    let mut headers = vec![
        HeaderName::new_from_ascii_str("From"),
        HeaderName::new_from_ascii_str("To"),
        HeaderName::new_from_ascii_str("Subject"),
        HeaderName::new_from_ascii_str("Date"),
    ];
    if email.message_id.is_some() {
        headers.push(HeaderName::new_from_ascii_str("Message-ID"));
    }
    if email.reply_to.is_some() {
        headers.push(HeaderName::new_from_ascii_str("Reply-To"));
    }
    if email.in_reply_to.is_some() {
        headers.push(HeaderName::new_from_ascii_str("In-Reply-To"));
        headers.push(HeaderName::new_from_ascii_str("References"));
    }
    Ok(DkimConfig::new(
        key.selector.clone(),
        key.domain.clone(),
        signing_key,
        headers,
        DkimCanonicalization {
            header: DkimCanonicalizationType::Relaxed,
            body: DkimCanonicalizationType::Relaxed,
        },
    ))
}

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MailEvent {
    Bounce {
        email: String,
        #[serde(default)]
        permanent: bool,
        detail: Option<String>,
    },
    Complaint {
        email: String,
        detail: Option<String>,
    },
    Delivery {
        email: String,
    },
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailEvents {
    pub events: Vec<MailEvent>,
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct Suppression {
    pub email: String,
    pub reason: String,
    pub detail: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub async fn suppress(
    pool: &PgPool,
    email: &str,
    reason: &str,
    detail: Option<&str>,
) -> sqlx::Result<bool> {
    let email = email.trim().to_lowercase();
    if email.is_empty() || email.len() > 320 || !email.contains('@') {
        return Ok(false);
    }
    Ok(sqlx::query(
        "INSERT INTO email_suppressions (email, reason, detail) VALUES ($1, $2, left($3, 500))
         ON CONFLICT (email) DO NOTHING",
    )
    .bind(email)
    .bind(reason)
    .bind(detail)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

pub async fn unsuppress(pool: &PgPool, email: &str) -> sqlx::Result<bool> {
    Ok(
        sqlx::query("DELETE FROM email_suppressions WHERE email = lower($1)")
            .bind(email.trim())
            .execute(pool)
            .await?
            .rows_affected()
            == 1,
    )
}

pub async fn suppressions(pool: &PgPool, limit: i64) -> sqlx::Result<Vec<Suppression>> {
    sqlx::query_as(
        "SELECT email, reason, detail, created_at FROM email_suppressions ORDER BY created_at DESC LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
}

pub async fn apply_events(pool: &PgPool, events: &[MailEvent]) -> sqlx::Result<usize> {
    let mut added = 0;
    for event in events {
        let changed = match event {
            MailEvent::Bounce {
                email,
                permanent: true,
                detail,
            } => suppress(pool, email, "bounce", detail.as_deref()).await?,
            MailEvent::Complaint { email, detail } => {
                suppress(pool, email, "complaint", detail.as_deref()).await?
            }
            MailEvent::Bounce { .. } | MailEvent::Delivery { .. } => false,
        };
        if changed {
            added += 1;
        }
    }
    Ok(added)
}

#[cfg(test)]
mod dkim_tests {
    use super::*;

    #[test]
    fn replies_are_signed_with_the_domain_key() {
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        let key = DkimKey {
            domain: "acme.test".into(),
            selector: "ultrivly-abc".into(),
            private_key_pem: String::from_utf8(rsa.private_key_to_pem().unwrap()).unwrap(),
        };
        let email = Email {
            to: "pat@customer.test".into(),
            subject: "Re: Help".into(),
            body: "Hello".into(),
            message_id: Some("<1@acme.test>".into()),
            reply_to: Some("help@acme.test".into()),
            ..Email::default()
        };
        let mut message = Message::builder()
            .from("help@acme.test".parse::<Mailbox>().unwrap())
            .to("pat@customer.test".parse::<Mailbox>().unwrap())
            .reply_to("help@acme.test".parse::<Mailbox>().unwrap())
            .message_id(email.message_id.clone())
            .subject("Re: Help")
            .body("Hello".to_string())
            .unwrap();
        message.sign(&dkim_config(&key, &email).unwrap());
        let raw = String::from_utf8(message.formatted()).unwrap();
        let header = raw
            .lines()
            .find(|l| l.starts_with("DKIM-Signature:"))
            .expect("message carries a DKIM signature");
        assert!(raw.contains("d=acme.test"), "{header}");
        assert!(raw.contains("s=ultrivly-abc"));
        assert!(raw.contains("a=rsa-sha256"));
    }

    #[test]
    fn dkim_keys_are_not_printed() {
        let key = DkimKey {
            private_key_pem: "-----BEGIN RSA PRIVATE KEY-----secret".into(),
            ..DkimKey::default()
        };
        assert!(!format!("{key:?}").contains("secret"));
    }
}
