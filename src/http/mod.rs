


pub mod error;
mod routes;
mod security;

use std::future::Future;
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{DefaultBodyLimit, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{HeaderName, StatusCode};
use axum::middleware;
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use sqlx::PgPool;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use url::Url;
use uuid::Uuid;

use crate::audit::Actor;
use crate::http::error::ApiError;
use crate::identity::passkeys::Passkeys;
use crate::identity::sessions::{self, ABSOLUTE_LIFETIME, Session};
use crate::identity::sso::Sso;
use crate::integrations::api_credentials;
use crate::platform::blob::BlobStore;
use crate::platform::secrets::Secrets;

const MAX_BODY_BYTES: usize = 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Settings {
    pub public_url: Url,
    
    pub trusted_proxy_hops: usize,
}




#[derive(Clone, Copy)]
pub struct CookieNames {
    pub session: &'static str,
    pub mfa: &'static str,
    pub oidc: &'static str,
    pub saml: &'static str,
}

pub struct Inner {
    pub pool: PgPool,
    pub secrets: Secrets,
    pub sso: Sso,
    pub passkeys: Passkeys,
    pub blobs: BlobStore,
    pub public_url: String,
    pub public_origin: String,
    pub https: bool,
    pub cookies: CookieNames,
    pub trusted_proxy_hops: usize,
}

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

impl Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl AppState {
    pub fn new(
        pool: PgPool,
        secrets: Secrets,
        sso: Sso,
        blobs: BlobStore,
        settings: Settings,
    ) -> anyhow::Result<Self> {
        let passkeys = Passkeys::new(&settings.public_url, secrets.clone())?;
        let https = settings.public_url.scheme() == "https";
        let cookies = if https {
            CookieNames {
                session: "__Host-ultrivly_session",
                mfa: "__Host-ultrivly_mfa",
                oidc: "__Host-ultrivly_oidc",
                saml: "__Host-ultrivly_saml",
            }
        } else {
            CookieNames {
                session: "ultrivly_session",
                mfa: "ultrivly_mfa",
                oidc: "ultrivly_oidc",
                saml: "ultrivly_saml",
            }
        };
        Ok(Self(Arc::new(Inner {
            pool,
            secrets,
            sso,
            passkeys,
            blobs,
            public_url: settings
                .public_url
                .as_str()
                .trim_end_matches('/')
                .to_string(),
            public_origin: settings.public_url.origin().ascii_serialization(),
            https,
            cookies,
            trusted_proxy_hops: settings.trusted_proxy_hops,
        })))
    }

    
    pub fn cookie(&self, name: &'static str, value: String, max_age: Duration) -> Cookie<'static> {
        Cookie::build((name, value))
            .http_only(true)
            .secure(self.https)
            .same_site(SameSite::Lax)
            .path("/")
            .max_age(cookie::time::Duration::seconds(max_age.as_secs() as i64))
            .build()
    }

    pub fn session_cookie(&self, token: String) -> Cookie<'static> {
        self.cookie(self.cookies.session, token, ABSOLUTE_LIFETIME)
    }

    pub fn cross_site_cookie(
        &self,
        name: &'static str,
        value: String,
        max_age: Duration,
    ) -> Cookie<'static> {
        let mut cookie = self.cookie(name, value, max_age);
        if self.https {
            cookie.set_same_site(SameSite::None);
        }
        cookie
    }

    pub fn expired(&self, name: &'static str) -> Cookie<'static> {
        self.cookie(name, String::new(), Duration::ZERO)
    }
}


pub struct Authenticated(pub Session);

impl FromRequestParts<AppState> for Authenticated {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        let token = jar
            .get(state.cookies.session)
            .map(|c| c.value().to_string())
            .ok_or_else(ApiError::unauthenticated)?;
        let mut conn = state.pool.acquire().await?;
        let session = sessions::authenticate(&mut conn, &token)
            .await?
            .ok_or_else(ApiError::unauthenticated)?;
        Ok(Authenticated(session))
    }
}

pub enum Caller {
    Session(Session),
    ApiKey(api_credentials::Authenticated),
}

impl Caller {
    pub fn actor(&self) -> Actor {
        match self {
            Caller::Session(session) => Actor::User(session.user_id),
            Caller::ApiKey(key) => key.actor(),
        }
    }
}

impl FromRequestParts<AppState> for Caller {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let bearer = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim);
        if let Some(token) = bearer {
            let mut conn = state.pool.acquire().await?;
            return api_credentials::authenticate(&mut conn, token)
                .await?
                .map(Caller::ApiKey)
                .ok_or_else(ApiError::unauthenticated);
        }
        Authenticated::from_request_parts(parts, state)
            .await
            .map(|Authenticated(session)| Caller::Session(session))
    }
}

pub async fn org_actor(state: &AppState, caller: &Caller, org_id: Uuid) -> Result<Actor, ApiError> {
    match caller {
        Caller::Session(session) => {
            require_org_access(state, session, org_id).await?;
            Ok(Actor::User(session.user_id))
        }
        Caller::ApiKey(key) if key.org_id == org_id => Ok(key.actor()),
        Caller::ApiKey(_) => Err(ApiError::not_found()),
    }
}




pub async fn require_org_access(
    state: &AppState,
    session: &Session,
    org_id: Uuid,
) -> Result<(), ApiError> {
    let mut conn = state.pool.acquire().await?;
    sessions::check_org_access(&mut conn, session, org_id).await??;
    Ok(())
}

pub fn router(state: AppState) -> Router {
    let request_id = HeaderName::from_static("x-request-id");
    let mut app = routes::router()
        .fallback(|| async { ApiError::not_found() })
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security::csrf,
        ))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ));
    for (name, value) in security::security_headers(state.https) {
        app = app.layer(SetResponseHeaderLayer::if_not_present(name, value));
    }
    app.layer(PropagateRequestIdLayer::new(request_id.clone()))
        
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &axum::http::Request<_>| {
                tracing::info_span!(
                    "http",
                    method = %request.method(),
                    path = %request.uri().path(),
                    request_id = ?request.headers().get("x-request-id"),
                )
            }),
        )
        .layer(SetRequestIdLayer::new(request_id, MakeRequestUuid))
        .with_state(state)
}

pub async fn serve(
    state: AppState,
    addr: SocketAddr,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "listening");
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await?;
    Ok(())
}
