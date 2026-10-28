

pub mod accounts;
pub mod emails;
pub mod invitations;
pub mod members;
pub mod mfa;
pub mod orgs;
pub mod passkeys;
pub mod roles;
pub mod saml;
pub mod sessions;
pub mod sso;

use serde_json::json;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

use crate::audit::{self, Actor};
use crate::cases;
use crate::platform::authz::{ADMIN_ROLE_KEY, BUILTIN_ROLES};

pub struct NewOrganization<'a> {
    pub name: &'a str,
    pub slug: &'a str,
    pub workspace_name: &'a str,
    pub workspace_slug: &'a str,
    
    pub owner_user_id: Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreatedOrganization {
    pub org_id: Uuid,
    pub workspace_id: Uuid,
    pub owner_membership_id: Uuid,
}

#[derive(Debug, thiserror::Error)]
pub enum CreateOrganizationError {
    
    #[error("{field} {reason}")]
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
    #[error("an organization with this slug already exists")]
    SlugTaken,
    #[error("owner user not found or disabled")]
    OwnerNotFound,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}




pub async fn create_organization(
    conn: &mut PgConnection,
    new: NewOrganization<'_>,
) -> Result<CreatedOrganization, CreateOrganizationError> {
    validate_name("name", new.name)?;
    validate_slug("slug", new.slug)?;
    validate_name("workspace_name", new.workspace_name)?;
    validate_slug("workspace_slug", new.workspace_slug)?;

    let mut tx = conn.begin().await?;

    let owner_active: Option<bool> =
        sqlx::query_scalar("SELECT disabled_at IS NULL FROM users WHERE id = $1 FOR SHARE")
            .bind(new.owner_user_id)
            .fetch_optional(&mut *tx)
            .await?;
    if owner_active != Some(true) {
        return Err(CreateOrganizationError::OwnerNotFound);
    }

    let org_id = Uuid::now_v7();
    sqlx::query("INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind(new.name.trim())
        .bind(new.slug)
        .execute(&mut *tx)
        .await
        .map_err(
            |err| match err.as_database_error().and_then(|e| e.constraint()) {
                Some("organizations_slug_key") => CreateOrganizationError::SlugTaken,
                _ => err.into(),
            },
        )?;

    let workspace_id = Uuid::now_v7();
    sqlx::query("INSERT INTO workspaces (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
        .bind(workspace_id)
        .bind(org_id)
        .bind(new.workspace_name.trim())
        .bind(new.workspace_slug)
        .execute(&mut *tx)
        .await?;

    let mut admin_role_id = None;
    for role in BUILTIN_ROLES {
        let role_id = Uuid::now_v7();
        let permissions = role.permissions.iter().copied().collect();
        roles::insert_role(
            &mut tx,
            org_id,
            role_id,
            role.key,
            role.name,
            true,
            &permissions,
        )
        .await?;

        if role.key == ADMIN_ROLE_KEY {
            admin_role_id = Some(role_id);
        }
    }
    let admin_role_id = admin_role_id.expect("BUILTIN_ROLES includes the admin role");

    let owner_membership_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO memberships (id, org_id, user_id, status) VALUES ($1, $2, $3, 'active')",
    )
    .bind(owner_membership_id)
    .bind(org_id)
    .bind(new.owner_user_id)
    .execute(&mut *tx)
    .await?;

    
    sqlx::query(
        "INSERT INTO membership_roles (org_id, membership_id, role_id, workspace_id)
         VALUES ($1, $2, $3, NULL)",
    )
    .bind(org_id)
    .bind(owner_membership_id)
    .bind(admin_role_id)
    .execute(&mut *tx)
    .await?;

    cases::seed_org_defaults(&mut tx, org_id).await?;

    audit::record(
        &mut tx,
        audit::Event {
            org_id: Some(org_id),
            actor: Actor::User(new.owner_user_id),
            action: "organization.created",
            target_type: "organization",
            target_id: org_id,
            metadata: json!({ "slug": new.slug, "workspace_id": workspace_id }),
        },
    )
    .await?;

    tx.commit().await?;
    Ok(CreatedOrganization {
        org_id,
        workspace_id,
        owner_membership_id,
    })
}

fn validate_name(field: &'static str, name: &str) -> Result<(), CreateOrganizationError> {
    let len = name.trim().chars().count();
    if len == 0 || len > 200 {
        return Err(CreateOrganizationError::Invalid {
            field,
            reason: "must be between 1 and 200 characters",
        });
    }
    Ok(())
}



pub(crate) fn is_valid_slug(slug: &str) -> bool {
    (1..=63).contains(&slug.len())
        && slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !slug.starts_with('-')
        && !slug.ends_with('-')
}

pub(crate) fn validate_slug_value(
    field: &'static str,
    slug: &str,
) -> Result<(), crate::platform::error::ServiceError> {
    if is_valid_slug(slug) {
        Ok(())
    } else {
        Err(crate::platform::error::invalid(
            field,
            "must be 1-63 lowercase letters, digits, or hyphens, not starting or ending with a hyphen",
        ))
    }
}

fn validate_slug(field: &'static str, slug: &str) -> Result<(), CreateOrganizationError> {
    let valid = (1..=63).contains(&slug.len())
        && slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !slug.starts_with('-')
        && !slug.ends_with('-');
    if !valid {
        return Err(CreateOrganizationError::Invalid {
            field,
            reason: "must be 1-63 lowercase letters, digits, or hyphens, not starting or ending with a hyphen",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_slug;

    #[test]
    fn slug_validation_matches_the_database_rule() {
        for ok in ["a", "acme", "acme-support", "a1", &"a".repeat(63)] {
            assert!(validate_slug("slug", ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "-acme",
            "acme-",
            "Acme",
            "acme_co",
            "acmé",
            &"a".repeat(64),
        ] {
            assert!(validate_slug("slug", bad).is_err(), "{bad}");
        }
    }
}
