







use std::time::Duration;

use serde_json::json;
use sqlx::{Connection, PgConnection};
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Webauthn,
    WebauthnBuilder,
};

use crate::identity::accounts::record;
use crate::identity::mfa::{self, MfaError};
use crate::identity::sessions::{ClientInfo, NewSession, Session};
use crate::platform::secrets::Secrets;

const CEREMONY_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_PASSKEYS: i64 = 10;

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct PasskeyInfo {
    pub id: Uuid,
    pub label: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub struct Passkeys {
    webauthn: Webauthn,
    secrets: Secrets,
}

impl Passkeys {
    
    pub fn new(public_url: &Url, secrets: Secrets) -> anyhow::Result<Self> {
        let host = public_url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("ULTRIVLY_PUBLIC_URL has no host"))?;
        let webauthn = WebauthnBuilder::new(host, public_url)?
            .rp_name("Ultrivly")
            .build()?;
        Ok(Self { webauthn, secrets })
    }

    
    
    pub async fn start_registration(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        label: &str,
    ) -> Result<(Uuid, CreationChallengeResponse), MfaError> {
        let label = label.trim();
        if label.is_empty() || label.chars().count() > 100 {
            return Err(MfaError::InvalidName);
        }
        let (email, display_name): (String, String) =
            sqlx::query_as("SELECT email, display_name FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_one(&mut *conn)
                .await?;
        let existing = self.load(conn, user_id).await?;
        if existing.len() as i64 >= MAX_PASSKEYS {
            return Err(MfaError::TooManyFactors);
        }
        let exclude = existing.iter().map(|(_, p)| p.cred_id().clone()).collect();
        let (options, state) = self
            .webauthn
            .start_passkey_registration(user_id, &email, &display_name, Some(exclude))
            .map_err(|e| MfaError::Internal(anyhow::anyhow!("passkey registration: {e}")))?;

        let id = self
            .store_ceremony(
                conn,
                user_id,
                "registration",
                Some(label),
                serde_json::to_vec(&state)?,
            )
            .await?;
        Ok((id, options))
    }

    
    
    pub async fn finish_registration(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        ceremony_id: Uuid,
        credential: &RegisterPublicKeyCredential,
        session: Option<&Session>,
    ) -> Result<Vec<String>, MfaError> {
        let mut tx = conn.begin().await?;
        let (state, label) = self
            .take_ceremony(&mut tx, user_id, ceremony_id, "registration")
            .await?;
        let state: PasskeyRegistration = serde_json::from_slice(&state)?;
        let passkey = self
            .webauthn
            .finish_passkey_registration(credential, &state)
            .map_err(|_| MfaError::InvalidCode)?;

        let first_factor = !mfa::has_mfa(&mut tx, user_id).await?;
        let factor_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO mfa_factors (id, user_id, kind, label, secret_ciphertext, credential_id, confirmed_at)
             VALUES ($1, $2, 'webauthn', $3, $4, $5, now())",
        )
        .bind(factor_id)
        .bind(user_id)
        .bind(label.unwrap_or_else(|| "Passkey".into()))
        .bind(self.seal(factor_id, &passkey)?)
        .bind(passkey.cred_id().as_ref())
        .execute(&mut *tx)
        .await
        .map_err(|err| match err.as_database_error().and_then(|e| e.constraint()) {
            Some("mfa_factors_credential_key") => MfaError::AlreadyEnrolled,
            _ => err.into(),
        })?;

        let codes = if first_factor {
            mfa::replace_recovery_codes(&mut tx, user_id).await?
        } else {
            Vec::new()
        };
        if let Some(session) = session.filter(|s| s.user_id == user_id) {
            mfa::mark_session_verified(&mut tx, session.id).await?;
        }
        record(
            &mut tx,
            user_id,
            "user.mfa_enabled",
            json!({ "kind": "webauthn" }),
        )
        .await?;
        tx.commit().await?;
        Ok(codes)
    }

    pub async fn list(conn: &mut PgConnection, user_id: Uuid) -> sqlx::Result<Vec<PasskeyInfo>> {
        sqlx::query_as(
            "SELECT id, label, created_at, last_used_at FROM mfa_factors
             WHERE user_id = $1 AND kind = 'webauthn' ORDER BY created_at",
        )
        .bind(user_id)
        .fetch_all(conn)
        .await
    }

    
    pub async fn remove(
        conn: &mut PgConnection,
        user_id: Uuid,
        factor_id: Uuid,
    ) -> Result<(), MfaError> {
        let mut tx = conn.begin().await?;
        let removed = sqlx::query(
            "DELETE FROM mfa_factors WHERE id = $1 AND user_id = $2 AND kind = 'webauthn'",
        )
        .bind(factor_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if removed == 0 {
            return Err(MfaError::NotEnrolled);
        }
        mfa::remove_recovery_codes_if_unused(&mut tx, user_id).await?;
        record(
            &mut tx,
            user_id,
            "user.mfa_disabled",
            json!({ "kind": "webauthn", "factor_id": factor_id }),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    
    
    pub async fn start_challenge(
        &self,
        conn: &mut PgConnection,
        challenge: &str,
    ) -> Result<(Uuid, RequestChallengeResponse), MfaError> {
        let mut tx = conn.begin().await?;
        let pending = mfa::lock_challenge(&mut tx, challenge).await?;
        let passkeys: Vec<Passkey> = self
            .load(&mut tx, pending.user_id)
            .await?
            .into_iter()
            .map(|(_, p)| p)
            .collect();
        if passkeys.is_empty() {
            return Err(MfaError::NotEnrolled);
        }
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| MfaError::Internal(anyhow::anyhow!("passkey authentication: {e}")))?;
        let id = self
            .store_ceremony(
                &mut tx,
                pending.user_id,
                "authentication",
                None,
                serde_json::to_vec(&state)?,
            )
            .await?;
        tx.commit().await?;
        Ok((id, options))
    }

    
    
    pub async fn complete_challenge(
        &self,
        conn: &mut PgConnection,
        challenge: &str,
        ceremony_id: Uuid,
        credential: &PublicKeyCredential,
        client: &ClientInfo,
    ) -> Result<NewSession, MfaError> {
        let mut tx = conn.begin().await?;
        let pending = mfa::lock_challenge(&mut tx, challenge).await?;
        let (state, _) = self
            .take_ceremony(&mut tx, pending.user_id, ceremony_id, "authentication")
            .await?;
        let state: PasskeyAuthentication = serde_json::from_slice(&state)?;

        let Ok(result) = self
            .webauthn
            .finish_passkey_authentication(credential, &state)
        else {
            mfa::fail_challenge(&mut tx, &pending).await?;
            tx.commit().await?;
            return Err(MfaError::InvalidCode);
        };

        
        for (factor_id, mut passkey) in self.load(&mut tx, pending.user_id).await? {
            if passkey.cred_id() == result.cred_id() {
                passkey.update_credential(&result);
                sqlx::query("UPDATE mfa_factors SET secret_ciphertext = $2, last_used_at = now() WHERE id = $1")
                    .bind(factor_id)
                    .bind(self.seal(factor_id, &passkey)?)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        let session = mfa::finish_challenge(&mut tx, &pending, "passkey", client).await?;
        tx.commit().await?;
        Ok(session)
    }

    async fn load(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
    ) -> Result<Vec<(Uuid, Passkey)>, MfaError> {
        let rows: Vec<(Uuid, Vec<u8>)> = sqlx::query_as(
            "SELECT id, secret_ciphertext FROM mfa_factors
             WHERE user_id = $1 AND kind = 'webauthn' AND confirmed_at IS NOT NULL",
        )
        .bind(user_id)
        .fetch_all(conn)
        .await?;
        rows.into_iter()
            .map(|(id, ciphertext)| {
                let plaintext = self.secrets.decrypt(&factor_context(id), &ciphertext)?;
                Ok((
                    id,
                    serde_json::from_slice(&plaintext).map_err(anyhow::Error::from)?,
                ))
            })
            .collect()
    }

    fn seal(&self, factor_id: Uuid, passkey: &Passkey) -> Result<Vec<u8>, MfaError> {
        Ok(self.secrets.encrypt(
            &factor_context(factor_id),
            &serde_json::to_vec(passkey).map_err(anyhow::Error::from)?,
        ))
    }

    async fn store_ceremony(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        purpose: &str,
        label: Option<&str>,
        state: Vec<u8>,
    ) -> Result<Uuid, MfaError> {
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO webauthn_ceremonies (id, user_id, purpose, label, state_ciphertext, expires_at)
             VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))",
        )
        .bind(id)
        .bind(user_id)
        .bind(purpose)
        .bind(label)
        .bind(self.secrets.encrypt(&ceremony_context(id), &state))
        .bind(CEREMONY_TTL.as_secs_f64())
        .execute(conn)
        .await?;
        Ok(id)
    }

    
    async fn take_ceremony(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        ceremony_id: Uuid,
        purpose: &str,
    ) -> Result<(Vec<u8>, Option<String>), MfaError> {
        let row: Option<(Vec<u8>, Option<String>)> = sqlx::query_as(
            "DELETE FROM webauthn_ceremonies
             WHERE id = $1 AND user_id = $2 AND purpose = $3 AND expires_at > now()
             RETURNING state_ciphertext, label",
        )
        .bind(ceremony_id)
        .bind(user_id)
        .bind(purpose)
        .fetch_optional(conn)
        .await?;
        let (ciphertext, label) = row.ok_or(MfaError::InvalidChallenge)?;
        Ok((
            self.secrets
                .decrypt(&ceremony_context(ceremony_id), &ciphertext)?,
            label,
        ))
    }
}

fn factor_context(factor_id: Uuid) -> String {
    format!("mfa_factor:{factor_id}")
}

fn ceremony_context(ceremony_id: Uuid) -> String {
    format!("webauthn_ceremony:{ceremony_id}")
}

impl From<serde_json::Error> for MfaError {
    fn from(err: serde_json::Error) -> Self {
        MfaError::Internal(err.into())
    }
}
