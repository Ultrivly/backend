use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;
use ultrivly::config::Deployment;
use ultrivly::http::{self, AppState, Settings};
use ultrivly::identity::sso::Sso;
use ultrivly::platform::blob::BlobStore;
use ultrivly::platform::mail::{Email, Mailer};
use ultrivly::platform::net::{HttpClient, NetPolicy};
use ultrivly::platform::secrets::Secrets;
use ultrivly::worker::Worker;
use uuid::Uuid;

pub const ORIGIN: &str = "https://ultrivly.test";
pub const SESSION: &str = "__Host-ultrivly_session";
pub const PASSWORD: &str = "correct horse battery staple";

pub struct App {
    pub router: Router,
    pub pool: PgPool,
    pub worker: Worker,
    pub outbox: Arc<Mutex<Vec<Email>>>,
}

pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Value,
}

impl Reply {
    pub fn cookie(&self, name: &str) -> Option<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|c| c.starts_with(&format!("{name}=")))
            .map(str::to_string)
    }

    pub fn cookie_value(&self, name: &str) -> Option<String> {
        self.cookie(name)
            .and_then(|c| {
                c.split(';')
                    .next()
                    .map(|kv| kv[name.len() + 1..].to_string())
            })
            .filter(|v| !v.is_empty())
    }
}

impl App {
    pub async fn new(pool: PgPool) -> Self {
        Self::with_ip(pool, [203, 0, 113, 7]).await
    }

    pub async fn with_ip(pool: PgPool, ip: [u8; 4]) -> Self {
        let secrets = Secrets::from_base64_key(&Secrets::generate_key()).unwrap();
        let net = HttpClient::new(NetPolicy::new(Deployment::Cloud, &[])).unwrap();
        let sso = Sso::new(secrets.clone(), net, ORIGIN, vec![]).unwrap();
        let state = AppState::new(
            pool.clone(),
            secrets.clone(),
            sso,
            BlobStore::in_memory(),
            Settings {
                public_url: ORIGIN.parse().unwrap(),
                trusted_proxy_hops: 0,
            },
        )
        .unwrap();
        let router = http::router(state).layer(MockConnectInfo(SocketAddr::from((ip, 40000))));
        let (mailer, outbox) = Mailer::memory();
        let worker = Worker {
            pool: pool.clone(),
            secrets,
            mailer,
            public_url: ORIGIN.into(),
            blobs: None,
            http: HttpClient::new(NetPolicy::new(Deployment::SelfHosted, &["127.0.0.1".into()])).unwrap(),
            id: "test".into(),
        };
        Self {
            router,
            pool,
            worker,
            outbox,
        }
    }

    
    pub async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        session: Option<&str>,
    ) -> Reply {
        self.raw(method, path, body, session, Some(ORIGIN)).await
    }

    pub async fn raw(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        session: Option<&str>,
        origin: Option<&str>,
    ) -> Reply {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(origin) = origin {
            request = request.header(header::ORIGIN, origin);
        }
        if let Some(token) = session {
            request = request.header(header::COOKIE, format!("{SESSION}={token}"));
        }
        let request = match body {
            Some(body) => request
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        }
        .unwrap();
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        Reply {
            status,
            headers,
            body,
        }
    }

    pub async fn bearer(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        token: &str,
    ) -> Reply {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"));
        let request = match body {
            Some(body) => request
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string())),
            None => {
                request = request.header(header::ACCEPT, "application/json");
                request.body(Body::empty())
            }
        }
        .unwrap();
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        Reply {
            status,
            headers,
            body,
        }
    }

    pub async fn upload(
        &self,
        path: &str,
        content_type: &str,
        bytes: Vec<u8>,
        session: &str,
    ) -> Reply {
        let request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::ORIGIN, ORIGIN)
            .header(header::COOKIE, format!("{SESSION}={session}"))
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::from(bytes))
            .unwrap();
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into()));
        Reply {
            status,
            headers,
            body,
        }
    }

    
    pub async fn deliver(&self) -> Vec<Email> {
        while self.worker.run_once().await.unwrap() {}
        std::mem::take(&mut *self.outbox.lock().unwrap())
    }

    pub async fn sign_up_and_verify(&self, email: &str) -> Uuid {
        let reply = self
            .call(
                Method::POST,
                "/api/v1/auth/sign-up",
                Some(json!({ "email": email, "display_name": "Sam", "password": PASSWORD })),
                None,
            )
            .await;
        assert_eq!(reply.status, StatusCode::ACCEPTED);
        let token = token_in(&self.deliver().await, email);
        let reply = self
            .call(
                Method::POST,
                "/api/v1/auth/verify-email",
                Some(json!({ "token": token })),
                None,
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
            .bind(email)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    pub async fn sign_in(&self, email: &str) -> String {
        let reply = self
            .call(
                Method::POST,
                "/api/v1/auth/sign-in",
                Some(json!({ "email": email, "password": PASSWORD })),
                None,
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        reply.cookie_value(SESSION).expect("session cookie")
    }
}


pub fn token_in(emails: &[Email], to: &str) -> String {
    let email = emails
        .iter()
        .find(|e| e.to == to)
        .expect("an email to the address");
    let start = email.body.find("#token=").expect("a link with a token") + "#token=".len();
    email.body[start..]
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
