



use std::sync::{Arc, Mutex};

use anyhow::{Context, bail};
use lettre::message::Mailbox;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::config::Deployment;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Email {
    pub to: String,
    pub subject: String,
    
    pub body: String,
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
                let message = Message::builder()
                    .from(from.clone())
                    .to(email.to.parse().context("invalid recipient address")?)
                    
                    .subject(email.subject.replace(['\r', '\n'], " "))
                    .body(email.body.clone())?;
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
