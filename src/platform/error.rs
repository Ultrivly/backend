use crate::platform::authz::{AuthzError, Permission};

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("permission denied")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("{field} {reason}")]
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
    #[error("{message}")]
    Conflict {
        code: &'static str,
        message: &'static str,
    },
    #[error("you cannot grant permissions you do not have: {}",
        .0.iter().map(|p| p.as_str()).collect::<Vec<_>>().join(", "))]
    CannotGrant(Vec<Permission>),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

pub type ServiceResult<T> = Result<T, ServiceError>;

impl From<AuthzError> for ServiceError {
    fn from(err: AuthzError) -> Self {
        match err {
            AuthzError::Forbidden => ServiceError::Forbidden,
            AuthzError::Database(err) => ServiceError::Database(err),
        }
    }
}

pub fn invalid(field: &'static str, reason: &'static str) -> ServiceError {
    ServiceError::Invalid { field, reason }
}

pub fn conflict(code: &'static str, message: &'static str) -> ServiceError {
    ServiceError::Conflict { code, message }
}

pub fn text(field: &'static str, value: &str, max: usize) -> Result<String, ServiceError> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > max {
        return Err(invalid(field, "has an invalid length"));
    }
    Ok(value.to_string())
}

pub fn unique_violation(err: &sqlx::Error, constraint: &str) -> bool {
    err.as_database_error()
        .and_then(|e| e.constraint())
        .is_some_and(|c| c == constraint)
}
