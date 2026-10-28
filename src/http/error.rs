


use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::identity::accounts::AuthError;
use crate::identity::invitations::InvitationError;
use crate::identity::mfa::MfaError;
use crate::identity::sessions::OrgAccessError;
use crate::identity::sso::SsoError;
use crate::platform::error::ServiceError;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub field: Option<&'static str>,
    pub retry_after_secs: Option<u64>,
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            field: None,
            retry_after_secs: None,
        }
    }

    pub fn field(mut self, field: &'static str) -> Self {
        self.field = Some(field);
        self
    }

    pub fn unauthenticated() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "sign in to continue",
        )
    }

    pub fn forbidden() -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", "permission denied")
    }

    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "not found")
    }

    pub fn rate_limited(retry_after_secs: u64) -> Self {
        Self {
            retry_after_secs: Some(retry_after_secs),
            ..Self::new(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "too many requests; try again later",
            )
        }
    }

    
    pub fn internal(err: impl std::fmt::Display) -> Self {
        tracing::error!("internal error: {err:#}");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "something went wrong",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = json!({ "code": self.code, "message": self.message });
        if let Some(field) = self.field {
            body["field"] = json!(field);
        }
        let mut response = (self.status, Json(json!({ "error": body }))).into_response();
        if let Some(secs) = self.retry_after_secs {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(secs));
        }
        response
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        Self::internal(err)
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        Self::internal(format!("{err:#}"))
    }
}

impl From<AuthError> for ApiError {
    fn from(err: AuthError) -> Self {
        use StatusCode as S;
        let message = err.to_string();
        match err {
            AuthError::InvalidCredentials => {
                Self::new(S::UNAUTHORIZED, "invalid_credentials", message)
            }
            AuthError::TooManyAttempts => Self {
                retry_after_secs: Some(60),
                ..Self::new(S::TOO_MANY_REQUESTS, "too_many_attempts", message)
            },
            AuthError::InvalidEmail => {
                Self::new(S::UNPROCESSABLE_ENTITY, "invalid_email", message).field("email")
            }
            AuthError::InvalidDisplayName => {
                Self::new(S::UNPROCESSABLE_ENTITY, "invalid_display_name", message)
                    .field("display_name")
            }
            AuthError::WeakPassword(_) => {
                Self::new(S::UNPROCESSABLE_ENTITY, "weak_password", message).field("password")
            }
            
            AuthError::EmailTaken => Self::new(S::CONFLICT, "email_taken", message),
            AuthError::InvalidToken => Self::new(S::BAD_REQUEST, "invalid_token", message),
            AuthError::InvalidCode => Self::new(S::UNAUTHORIZED, "invalid_code", message),
            AuthError::Database(err) => Self::internal(err),
            AuthError::Internal(err) => Self::internal(format!("{err:#}")),
        }
    }
}

impl From<MfaError> for ApiError {
    fn from(err: MfaError) -> Self {
        use StatusCode as S;
        let message = err.to_string();
        match err {
            MfaError::AlreadyEnrolled => Self::new(S::CONFLICT, "mfa_already_enabled", message),
            MfaError::NotEnrolled => Self::new(S::CONFLICT, "mfa_not_enabled", message),
            MfaError::InvalidCode => Self::new(S::UNAUTHORIZED, "invalid_code", message),
            MfaError::InvalidChallenge => {
                Self::new(S::UNAUTHORIZED, "mfa_challenge_expired", message)
            }
            MfaError::InvalidName => {
                Self::new(S::UNPROCESSABLE_ENTITY, "invalid_name", message).field("label")
            }
            MfaError::TooManyFactors => Self::new(S::CONFLICT, "too_many_passkeys", message),
            MfaError::Database(err) => Self::internal(err),
            MfaError::Internal(err) => Self::internal(format!("{err:#}")),
        }
    }
}

impl From<SsoError> for ApiError {
    fn from(err: SsoError) -> Self {
        use StatusCode as S;
        let message = err.to_string();
        match err {
            SsoError::Forbidden => Self::forbidden(),
            SsoError::CannotGrant(_) => Self::new(S::FORBIDDEN, "cannot_grant", message),
            SsoError::Invalid { field, .. } => {
                Self::new(S::UNPROCESSABLE_ENTITY, "invalid", message).field(field)
            }
            SsoError::NameTaken => Self::new(S::CONFLICT, "name_taken", message).field("name"),
            SsoError::NotFound | SsoError::Unavailable => {
                Self::new(S::NOT_FOUND, "sso_unavailable", message)
            }
            SsoError::InvalidState => Self::new(S::BAD_REQUEST, "sso_state_invalid", message),
            SsoError::Provider(detail) => {
                tracing::warn!("identity provider error: {detail}");
                Self::new(
                    S::BAD_GATEWAY,
                    "sso_provider_error",
                    "the identity provider could not complete sign-in",
                )
            }
            SsoError::EmailMissing => Self::new(S::BAD_REQUEST, "sso_email_missing", message),
            SsoError::EmailDomainNotAllowed => {
                Self::new(S::FORBIDDEN, "sso_domain_not_allowed", message)
            }
            SsoError::AccountExists => Self::new(S::CONFLICT, "sso_account_exists", message),
            SsoError::NotProvisioned => Self::new(S::FORBIDDEN, "sso_not_provisioned", message),
            SsoError::AccountDisabled => Self::new(S::FORBIDDEN, "account_disabled", message),
            SsoError::IdentityInUse => Self::new(S::CONFLICT, "sso_identity_in_use", message),
            SsoError::EmailNotVerified => Self::new(S::FORBIDDEN, "email_not_verified", message),
            SsoError::Auth(err) => err.into(),
            SsoError::Database(err) => Self::internal(err),
            SsoError::Internal(err) => Self::internal(format!("{err:#}")),
        }
    }
}

impl From<InvitationError> for ApiError {
    fn from(err: InvitationError) -> Self {
        use StatusCode as S;
        let message = err.to_string();
        match err {
            InvitationError::Forbidden => Self::forbidden(),
            InvitationError::CannotGrant(_) => Self::new(S::FORBIDDEN, "cannot_grant", message),
            InvitationError::InvalidEmail => {
                Self::new(S::UNPROCESSABLE_ENTITY, "invalid_email", message).field("email")
            }
            InvitationError::RoleNotFound => {
                Self::new(S::UNPROCESSABLE_ENTITY, "role_not_found", message).field("role_id")
            }
            InvitationError::WorkspaceNotFound => {
                Self::new(S::UNPROCESSABLE_ENTITY, "workspace_not_found", message)
                    .field("workspace_id")
            }
            InvitationError::AlreadyMember => Self::new(S::CONFLICT, "already_member", message),
            InvitationError::NotFound => Self::not_found(),
            InvitationError::InvalidToken => Self::new(S::BAD_REQUEST, "invalid_token", message),
            InvitationError::WrongAccount => {
                Self::new(S::FORBIDDEN, "invitation_wrong_account", message)
            }
            InvitationError::Database(err) => Self::internal(err),
        }
    }
}

impl From<OrgAccessError> for ApiError {
    fn from(err: OrgAccessError) -> Self {
        let code = match err {
            OrgAccessError::SsoRequired => "sso_required",
            OrgAccessError::MfaRequired => "mfa_required",
        };
        Self::new(StatusCode::FORBIDDEN, code, err.to_string())
    }
}

impl From<ServiceError> for ApiError {
    fn from(err: ServiceError) -> Self {
        use StatusCode as S;
        let message = err.to_string();
        match err {
            ServiceError::Forbidden => Self::forbidden(),
            ServiceError::NotFound => Self::not_found(),
            ServiceError::Invalid { field, .. } => {
                Self::new(S::UNPROCESSABLE_ENTITY, "invalid", message).field(field)
            }
            ServiceError::Conflict { code, .. } => Self::new(S::CONFLICT, code, message),
            ServiceError::CannotGrant(_) => Self::new(S::FORBIDDEN, "cannot_grant", message),
            ServiceError::Database(err) => Self::internal(err),
            ServiceError::Internal(err) => Self::internal(format!("{err:#}")),
        }
    }
}

impl From<crate::platform::authz::AuthzError> for ApiError {
    fn from(err: crate::platform::authz::AuthzError) -> Self {
        ServiceError::from(err).into()
    }
}

impl From<crate::identity::roles::RoleError> for ApiError {
    fn from(err: crate::identity::roles::RoleError) -> Self {
        use crate::identity::roles::RoleError as E;
        use StatusCode as S;
        let message = err.to_string();
        match err {
            E::Forbidden => Self::forbidden(),
            E::CannotGrant(_) => Self::new(S::FORBIDDEN, "cannot_grant", message),
            E::Invalid { field, .. } => {
                Self::new(S::UNPROCESSABLE_ENTITY, "invalid", message).field(field)
            }
            E::NameTaken => Self::new(S::CONFLICT, "name_taken", message).field("name"),
            E::NotFound => Self::not_found(),
            E::BuiltIn => Self::new(S::CONFLICT, "builtin_role", message),
            E::InUse { .. } => Self::new(S::CONFLICT, "role_in_use", message),
            E::Database(err) => Self::internal(err),
        }
    }
}

impl From<crate::identity::members::MemberError> for ApiError {
    fn from(err: crate::identity::members::MemberError) -> Self {
        use crate::identity::members::MemberError as E;
        use StatusCode as S;
        let message = err.to_string();
        match err {
            E::Forbidden => Self::forbidden(),
            E::CannotGrant(_) => Self::new(S::FORBIDDEN, "cannot_grant", message),
            E::MemberNotFound | E::RoleNotFound | E::WorkspaceNotFound => {
                Self::new(S::NOT_FOUND, "not_found", message)
            }
            E::AlreadyAssigned => Self::new(S::CONFLICT, "already_assigned", message),
            E::NotAssigned => Self::new(S::NOT_FOUND, "not_assigned", message),
            E::LastAdministrator => Self::new(S::CONFLICT, "last_administrator", message),
            E::Database(err) => Self::internal(err),
        }
    }
}

impl From<crate::platform::deletion::DeletionError> for ApiError {
    fn from(err: crate::platform::deletion::DeletionError) -> Self {
        use crate::platform::deletion::DeletionError as E;
        use StatusCode as S;
        let message = err.to_string();
        match err {
            E::NotFound => Self::not_found(),
            E::Forbidden => Self::forbidden(),
            E::ConfirmationMismatch => {
                Self::new(S::UNPROCESSABLE_ENTITY, "confirmation_mismatch", message)
                    .field("confirm")
            }
            E::AlreadyScheduled => Self::new(S::CONFLICT, "already_scheduled", message),
            E::NotScheduled => Self::new(S::CONFLICT, "not_scheduled", message),
            E::RetentionEnded => Self::new(S::CONFLICT, "retention_ended", message),
            E::Database(err) => Self::internal(err),
        }
    }
}
