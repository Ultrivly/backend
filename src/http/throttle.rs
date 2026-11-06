use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::header;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::CookieJar;
use sha2::{Digest, Sha256};

use crate::http::AppState;
use crate::http::error::ApiError;
use crate::http::security::forwarded_ip;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub per_caller: u32,
    pub per_ip: u32,
}

#[derive(Default)]
struct Window {
    minute: u64,
    callers: HashMap<[u8; 16], u32>,
    ips: HashMap<IpAddr, u32>,
}

pub struct Throttle {
    limits: Limits,
    window: Mutex<Window>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Allowed,
    Limited { retry_after_secs: u64 },
}

impl Throttle {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            window: Mutex::new(Window::default()),
        }
    }

    pub fn check(&self, ip: Option<IpAddr>, caller: Option<[u8; 16]>, now_secs: u64) -> Verdict {
        let minute = now_secs / 60;
        let mut window = self.window.lock().unwrap_or_else(|e| e.into_inner());
        if window.minute != minute {
            *window = Window {
                minute,
                ..Window::default()
            };
        }
        let limited = Verdict::Limited {
            retry_after_secs: 60 - now_secs % 60,
        };
        if let Some(ip) = ip.filter(|_| self.limits.per_ip > 0) {
            let count = window.ips.entry(ip).or_default();
            *count += 1;
            if *count > self.limits.per_ip {
                return limited;
            }
        }
        if let Some(caller) = caller.filter(|_| self.limits.per_caller > 0) {
            let count = window.callers.entry(caller).or_default();
            *count += 1;
            if *count > self.limits.per_caller {
                return limited;
            }
        }
        Verdict::Allowed
    }
}

fn caller_key(state: &AppState, request: &Request) -> Option<[u8; 16]> {
    let credential = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t.trim().to_string())
        .or_else(|| {
            CookieJar::from_headers(request.headers())
                .get(state.cookies.session)
                .map(|c| c.value().to_string())
        })?;
    let digest = Sha256::digest(credential.as_bytes());
    let mut key = [0; 16];
    key.copy_from_slice(&digest[..16]);
    Some(key)
}

pub async fn throttle(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let path = request.uri().path();
    if path == "/healthz" || path == "/readyz" {
        return next.run(request).await;
    }
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());
    let ip = forwarded_ip(request.headers(), state.trusted_proxy_hops).or(peer);
    let caller = caller_key(&state, &request);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    match state.throttle.check(ip, caller, now) {
        Verdict::Allowed => next.run(request).await,
        Verdict::Limited { retry_after_secs } => {
            metrics::counter!("ultrivly_http_throttled_total").increment(1);
            ApiError::rate_limited(retry_after_secs).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callers_and_addresses_have_separate_budgets() {
        let throttle = Throttle::new(Limits {
            per_caller: 2,
            per_ip: 3,
        });
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let a = Some([1; 16]);
        let b = Some([2; 16]);
        assert_eq!(throttle.check(Some(ip), a, 60), Verdict::Allowed);
        assert_eq!(throttle.check(Some(ip), a, 61), Verdict::Allowed);
        assert_eq!(
            throttle.check(Some(ip), a, 62),
            Verdict::Limited {
                retry_after_secs: 58
            }
        );
        assert_eq!(
            throttle.check(Some(ip), b, 63),
            Verdict::Limited {
                retry_after_secs: 57
            },
            "the address budget is shared by every caller behind it"
        );
        assert_eq!(
            throttle.check(Some(ip), a, 120),
            Verdict::Allowed,
            "budgets reset each minute"
        );
    }

    #[test]
    fn zero_disables_a_limit() {
        let throttle = Throttle::new(Limits {
            per_caller: 0,
            per_ip: 0,
        });
        for second in 0..1000 {
            assert_eq!(
                throttle.check(None, Some([1; 16]), second / 100),
                Verdict::Allowed
            );
        }
    }
}
