

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use axum::extract::{ConnectInfo, FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::http::AppState;
use crate::http::error::ApiError;
use crate::identity::sessions::ClientInfo;
use crate::platform::rate_limit::{self, Decision};








pub async fn csrf(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if is_saml_acs(request.uri().path())
        || matches!(
            *request.method(),
            Method::GET | Method::HEAD | Method::OPTIONS
        )
    {
        return next.run(request).await;
    }
    let headers = request.headers();
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    let cross_site = headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == "cross-site");
    let same_origin = |value: &str| value == state.public_origin;

    let allowed = match origin {
        Some(origin) => same_origin(origin) && !cross_site,
        None if has_our_cookies(&state, headers) => headers
            .get(header::REFERER)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|r| r.starts_with(&format!("{}/", state.public_origin))),
        None => !cross_site,
    };
    if !allowed {
        return ApiError::new(
            axum::http::StatusCode::FORBIDDEN,
            "cross_site_request",
            "request did not come from this site",
        )
        .into_response();
    }
    next.run(request).await
}

fn is_saml_acs(path: &str) -> bool {
    path.starts_with("/auth/saml/") && path.ends_with("/acs")
}

fn has_our_cookies(state: &AppState, headers: &HeaderMap) -> bool {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|c| c.contains(state.cookies.session) || c.contains(state.cookies.mfa))
}



pub fn security_headers(https: bool) -> Vec<(HeaderName, HeaderValue)> {
    let mut headers = vec![
        (
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ),
        (header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY")),
        (
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ),
        (
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
            ),
        ),
        (
            HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin"),
        ),
        (
            HeaderName::from_static("cross-origin-resource-policy"),
            HeaderValue::from_static("same-origin"),
        ),
        (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
    ];
    if https {
        headers.push((
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        ));
    }
    headers
}




pub struct Client(pub ClientInfo);

impl FromRequestParts<AppState> for Client {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let ConnectInfo(peer) = ConnectInfo::<SocketAddr>::from_request_parts(parts, state)
            .await
            .map_err(|_| ApiError::internal("missing connection info"))?;
        let peer = peer.ip();
        let ip = forwarded_ip(&parts.headers, state.trusted_proxy_hops).unwrap_or(peer);
        let user_agent = parts
            .headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|ua| ua.chars().take(512).collect());
        Ok(Client(ClientInfo {
            ip_address: Some(ip),
            user_agent,
        }))
    }
}

fn forwarded_ip(headers: &HeaderMap, hops: usize) -> Option<IpAddr> {
    if hops == 0 {
        return None;
    }
    let entries: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .collect();
    entries
        .len()
        .checked_sub(hops)
        .and_then(|i| entries[i].parse().ok())
}

impl Client {
    pub fn ip(&self) -> IpAddr {
        self.0.ip_address.expect("always set by the extractor")
    }
}


pub async fn limit_ip(
    state: &AppState,
    client: &Client,
    action: &str,
    limit: i32,
    window: Duration,
) -> Result<(), ApiError> {
    let key = format!("ip:{}:{action}", rate_limit::ip_key(client.ip()));
    limit_key(state, &key, limit, window).await
}

pub async fn limit_key(
    state: &AppState,
    key: &str,
    limit: i32,
    window: Duration,
) -> Result<(), ApiError> {
    match rate_limit::check(&state.pool, key, limit, window).await? {
        Decision::Allowed => Ok(()),
        Decision::Limited { retry_after_secs } => Err(ApiError::rate_limited(retry_after_secs)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusts_only_the_configured_number_of_proxies() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "6.6.6.6, 203.0.113.9, 10.0.0.2".parse().unwrap(),
        );
        assert_eq!(forwarded_ip(&headers, 0), None);
        
        assert_eq!(forwarded_ip(&headers, 1), Some("10.0.0.2".parse().unwrap()));
        assert_eq!(
            forwarded_ip(&headers, 2),
            Some("203.0.113.9".parse().unwrap())
        );
        
        assert_eq!(forwarded_ip(&headers, 5), None);
    }
}
