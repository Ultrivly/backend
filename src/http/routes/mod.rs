mod auth;
mod health;
mod invitations;
mod knowledge;
mod me;
mod oidc;
mod orgs;
mod work;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, patch, post, put};

use crate::http::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(health::live))
        .route("/readyz", get(health::ready))
        
        .route("/api/v1/auth/sign-up", post(auth::sign_up))
        .route("/api/v1/auth/sign-in", post(auth::sign_in))
        .route("/api/v1/auth/mfa", post(auth::complete_mfa))
        .route(
            "/api/v1/auth/mfa/passkey/start",
            post(auth::start_passkey_mfa),
        )
        .route(
            "/api/v1/auth/mfa/passkey/finish",
            post(auth::finish_passkey_mfa),
        )
        .route("/api/v1/auth/sign-out", post(auth::sign_out))
        .route("/api/v1/auth/verify-email", post(auth::verify_email))
        .route("/api/v1/auth/forgot-password", post(auth::forgot_password))
        .route("/api/v1/auth/reset-password", post(auth::reset_password))
        
        .route("/auth/oidc/start", get(oidc::start))
        .route("/auth/oidc/callback", get(oidc::callback))
        .route("/auth/saml/{id}/metadata", get(oidc::saml_metadata))
        .route("/auth/saml/{id}/acs", post(oidc::saml_acs))
        .route(
            "/auth/saml/{id}/slo",
            get(|| async { axum::response::Redirect::to("/sign-in") }),
        )
        
        .route("/api/v1/me", get(me::profile))
        .route("/api/v1/me/password", post(me::change_password))
        .route(
            "/api/v1/me/verification-email",
            post(me::resend_verification),
        )
        .route("/api/v1/me/sessions", get(me::list_sessions))
        .route("/api/v1/me/sessions/{id}", delete(me::revoke_session))
        .route(
            "/api/v1/me/sessions/sign-out-others",
            post(me::sign_out_others),
        )
        .route("/api/v1/me/mfa/totp", post(me::start_totp))
        .route("/api/v1/me/mfa/totp/confirm", post(me::confirm_totp))
        .route("/api/v1/me/mfa/totp/disable", post(me::disable_totp))
        .route(
            "/api/v1/me/mfa/recovery-codes",
            post(me::regenerate_recovery_codes),
        )
        .route("/api/v1/me/mfa/verify", post(me::verify_mfa))
        .route("/api/v1/me/mfa/passkeys", get(me::list_passkeys))
        .route("/api/v1/me/mfa/passkeys/start", post(me::start_passkey))
        .route("/api/v1/me/mfa/passkeys/finish", post(me::finish_passkey))
        .route(
            "/api/v1/me/mfa/passkeys/{id}/remove",
            post(me::remove_passkey),
        )
        .route("/api/v1/me/identities/link", post(oidc::link))
        
        .route(
            "/api/v1/orgs/{org_id}/invitations",
            get(invitations::list).post(invitations::create),
        )
        .route(
            "/api/v1/orgs/{org_id}/invitations/{id}",
            delete(invitations::revoke),
        )
        .route("/api/v1/invitations/accept", post(invitations::accept))
        .route("/api/v1/permissions", get(orgs::permission_catalogue))
        .route("/api/v1/orgs", get(orgs::list_mine).post(orgs::create))
        .route("/api/v1/orgs/{org_id}", get(orgs::get).patch(orgs::update))
        .route("/api/v1/orgs/{org_id}/delete", post(orgs::delete_org))
        .route("/api/v1/orgs/{org_id}/restore", post(orgs::restore_org))
        .route(
            "/api/v1/orgs/{org_id}/workspaces",
            get(orgs::list_workspaces).post(orgs::create_workspace),
        )
        .route(
            "/api/v1/orgs/{org_id}/workspaces/{id}",
            patch(orgs::update_workspace),
        )
        .route(
            "/api/v1/orgs/{org_id}/workspaces/{id}/delete",
            post(orgs::delete_workspace),
        )
        .route(
            "/api/v1/orgs/{org_id}/workspaces/{id}/restore",
            post(orgs::restore_workspace),
        )
        .route("/api/v1/orgs/{org_id}/members", get(orgs::list_members))
        .route(
            "/api/v1/orgs/{org_id}/members/{id}",
            patch(orgs::update_member).delete(orgs::remove_member),
        )
        .route(
            "/api/v1/orgs/{org_id}/members/{id}/roles",
            post(orgs::assign_role),
        )
        .route(
            "/api/v1/orgs/{org_id}/members/{id}/roles/remove",
            post(orgs::remove_role),
        )
        .route(
            "/api/v1/orgs/{org_id}/roles",
            get(orgs::list_roles).post(orgs::create_role),
        )
        .route(
            "/api/v1/orgs/{org_id}/roles/{id}",
            patch(orgs::update_role).delete(orgs::delete_role),
        )
        .route(
            "/api/v1/orgs/{org_id}/sso-connections",
            get(orgs::list_sso).post(orgs::create_sso),
        )
        .route(
            "/api/v1/orgs/{org_id}/sso-connections/{id}",
            patch(orgs::update_sso).delete(orgs::delete_sso),
        )
        .route(
            "/api/v1/orgs/{org_id}/sso-connections/{id}/saml-metadata",
            put(orgs::replace_saml_metadata),
        )
        .route(
            "/api/v1/orgs/{org_id}/audit-events",
            get(orgs::audit_events),
        )
        .route(
            "/api/v1/orgs/{org_id}/api-credentials",
            get(orgs::list_api_credentials).post(orgs::create_api_credential),
        )
        .route(
            "/api/v1/orgs/{org_id}/api-credentials/{id}/revoke",
            post(orgs::revoke_api_credential),
        )
        .route(
            "/api/v1/orgs/{org_id}/departments",
            get(work::list_departments).post(work::create_department),
        )
        .route(
            "/api/v1/orgs/{org_id}/departments/{id}",
            patch(work::rename_department).delete(work::delete_department),
        )
        .route(
            "/api/v1/orgs/{org_id}/teams",
            get(work::list_teams).post(work::create_team),
        )
        .route(
            "/api/v1/orgs/{org_id}/teams/{id}",
            patch(work::update_team).delete(work::delete_team),
        )
        .route(
            "/api/v1/orgs/{org_id}/teams/{id}/members/{user_id}",
            put(work::add_team_member).delete(work::remove_team_member),
        )
        .route(
            "/api/v1/orgs/{org_id}/queues",
            get(work::list_queues).post(work::create_queue),
        )
        .route(
            "/api/v1/orgs/{org_id}/queues/{id}",
            patch(work::update_queue).delete(work::delete_queue),
        )
        .route(
            "/api/v1/orgs/{org_id}/queues/{id}/cases",
            get(work::queue_cases),
        )
        .route("/api/v1/orgs/{org_id}/case-settings", get(work::statuses))
        .route(
            "/api/v1/orgs/{org_id}/contacts",
            get(work::list_contacts).post(work::create_contact),
        )
        .route(
            "/api/v1/orgs/{org_id}/contacts/{id}",
            get(work::get_contact).patch(work::update_contact),
        )
        .route(
            "/api/v1/orgs/{org_id}/cases",
            get(work::list_cases).post(work::create_case),
        )
        .route(
            "/api/v1/orgs/{org_id}/cases/{id}",
            get(work::get_case).patch(work::update_case),
        )
        .route(
            "/api/v1/orgs/{org_id}/cases/{id}/delete",
            post(work::delete_case),
        )
        .route(
            "/api/v1/orgs/{org_id}/cases/{id}/restore",
            post(work::restore_case),
        )
        .route(
            "/api/v1/orgs/{org_id}/cases/{id}/history",
            get(work::case_history),
        )
        .route(
            "/api/v1/orgs/{org_id}/cases/{id}/messages",
            get(work::list_messages).post(work::add_message),
        )
        .route(
            "/api/v1/orgs/{org_id}/cases/{id}/links",
            get(work::list_links).post(work::add_link),
        )
        .route(
            "/api/v1/orgs/{org_id}/cases/{id}/links/remove",
            post(work::remove_link),
        )
        .route(
            "/api/v1/orgs/{org_id}/cases/{id}/attachments",
            get(work::list_attachments)
                .post(work::upload_attachment)
                .layer(DefaultBodyLimit::max(
                    crate::cases::attachments::MAX_BYTES + 1024,
                )),
        )
        .route(
            "/api/v1/orgs/{org_id}/attachments/{id}",
            get(work::download_attachment),
        )
        .route(
            "/api/v1/orgs/{org_id}/attachments/{id}/delete",
            post(work::delete_attachment),
        )
        .route("/api/v1/portal/cases", get(work::portal_cases))
        .route("/api/v1/portal/cases/{id}", get(work::portal_case))
        .route(
            "/api/v1/portal/cases/{id}/messages",
            post(work::portal_reply),
        )
        .route(
            "/api/v1/portal/workspaces/{id}/cases",
            post(work::portal_submit),
        )
        .merge(extra())
}

fn extra() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/orgs/{org_id}/kb/categories",
            get(knowledge::list_categories).post(knowledge::create_category),
        )
        .route(
            "/api/v1/orgs/{org_id}/kb/categories/{id}",
            patch(knowledge::update_category).delete(knowledge::delete_category),
        )
        .route(
            "/api/v1/orgs/{org_id}/kb/articles",
            get(knowledge::list_articles).post(knowledge::create_article),
        )
        .route(
            "/api/v1/orgs/{org_id}/kb/articles/{id}",
            get(knowledge::get_article)
                .patch(knowledge::update_article)
                .delete(knowledge::delete_article),
        )
        .route("/api/v1/orgs/{org_id}/kb/articles/{id}/state", post(knowledge::set_article_state))
        .route("/api/v1/help/{org_slug}/articles", get(knowledge::help_center))
        .route("/api/v1/help/{org_slug}/articles/{slug}", get(knowledge::help_article))
}
