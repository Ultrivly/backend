












use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use openidconnect::{AsyncHttpClient, HttpRequest, HttpResponse};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use url::Url;

use crate::config::Deployment;

const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct NetPolicy {
    trusted_hosts: Vec<String>,
}

impl NetPolicy {
    
    pub fn new(deployment: Deployment, trusted_hosts: &[String]) -> Self {
        let trusted_hosts = match deployment {
            Deployment::Cloud => Vec::new(),
            Deployment::SelfHosted => trusted_hosts
                .iter()
                .map(|h| h.trim().to_ascii_lowercase())
                .filter(|h| !h.is_empty())
                .collect(),
        };
        Self { trusted_hosts }
    }

    pub fn is_trusted(&self, host: &str) -> bool {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        self.trusted_hosts
            .iter()
            .any(|h| h.eq_ignore_ascii_case(host))
    }

    
    pub fn check_url(&self, url: &Url) -> Result<(), NetError> {
        let host = url
            .host_str()
            .ok_or_else(|| NetError::Blocked(format!("{url} has no host")))?;
        if self.is_trusted(host) {
            return Ok(());
        }
        if url.scheme() != "https" {
            return Err(NetError::Blocked(format!("{url} must use https")));
        }
        if let Ok(ip) = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            && !is_public(ip)
        {
            return Err(NetError::Blocked(format!("{host} is not a public address")));
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("blocked destination: {0}")]
    Blocked(String),
    #[error("response larger than {MAX_RESPONSE_BYTES} bytes")]
    TooLarge,
    #[error(transparent)]
    Request(#[from] reqwest::Error),
    #[error(transparent)]
    Http(#[from] openidconnect::http::Error),
    #[error(transparent)]
    Url(#[from] url::ParseError),
}

#[derive(Clone)]
pub struct HttpClient {
    inner: reqwest::Client,
    policy: Arc<NetPolicy>,
}

impl HttpClient {
    pub fn new(policy: NetPolicy) -> anyhow::Result<Self> {
        let policy = Arc::new(policy);
        let inner = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(TIMEOUT)
            .connect_timeout(TIMEOUT)
            .user_agent(concat!("Ultrivly/", env!("CARGO_PKG_VERSION")))
            .dns_resolver(Arc::new(PublicOnlyResolver {
                policy: policy.clone(),
            }))
            .build()?;
        Ok(Self { inner, policy })
    }

    pub fn policy(&self) -> &NetPolicy {
        &self.policy
    }

    pub async fn post(
        &self,
        url: &str,
        headers: &[(&str, String)],
        body: Vec<u8>,
    ) -> Result<u16, NetError> {
        let mut request = openidconnect::http::Request::builder()
            .method(openidconnect::http::Method::POST)
            .uri(url);
        for (name, value) in headers {
            request = request.header(*name, value);
        }
        let response = self.send(request.body(body)?).await?;
        Ok(response.status().as_u16())
    }

    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, NetError> {
        self.policy
            .check_url(&Url::parse(&request.uri().to_string())?)?;
        let mut response = self.inner.execute(request.try_into()?).await?;

        let mut builder = openidconnect::http::Response::builder().status(response.status());
        for (name, value) in response.headers() {
            builder = builder.header(name, value);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(NetError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(builder.body(body)?)
    }
}


impl<'c> AsyncHttpClient<'c> for HttpClient {
    type Error = NetError;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, NetError>> + Send + Sync + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(self.send(request))
    }
}

struct PublicOnlyResolver {
    policy: Arc<NetPolicy>,
}

impl Resolve for PublicOnlyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        let trusted = self.policy.is_trusted(&host);
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|addr| trusted || is_public(addr.ip()))
                .collect();
            if addrs.is_empty() {
                return Err(format!("{host} does not resolve to a public address").into());
            }
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}



pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_public_v4(v4),
            None => is_public_v6(v6),
        },
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || a == 0
        || (a == 100 && (64..=127).contains(&b)) 
        || (a == 192 && b == 0 && c == 0) 
        || (a == 198 && (18..=19).contains(&b)) 
        || a >= 240) 
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (first & 0xfe00) == 0xfc00 
        || (first & 0xffc0) == 0xfe80 
        || first == 0x2001 && ip.segments()[1] == 0x0db8 
        || ip.segments()[..6] == [0, 0, 0, 0, 0, 0]) 
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_addresses() {
        for public in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(is_public(public.parse().unwrap()), "{public}");
        }
        for private in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(!is_public(private.parse().unwrap()), "{private}");
        }
    }

    #[test]
    fn checks_urls_against_the_policy() {
        let strict = NetPolicy::new(Deployment::SelfHosted, &[]);
        assert!(
            strict
                .check_url(&"https://login.example.com/".parse().unwrap())
                .is_ok()
        );
        for blocked in [
            "http://login.example.com/",
            "https://169.254.169.254/latest/meta-data",
            "https://[::1]/",
            "https://10.0.0.5/",
        ] {
            assert!(
                strict.check_url(&blocked.parse().unwrap()).is_err(),
                "{blocked}"
            );
        }

        let trusting = NetPolicy::new(Deployment::SelfHosted, &["keycloak.internal".into()]);
        assert!(
            trusting
                .check_url(&"http://keycloak.internal:8080/realms/x".parse().unwrap())
                .is_ok()
        );

        
        let cloud = NetPolicy::new(Deployment::Cloud, &["keycloak.internal".into()]);
        assert!(
            cloud
                .check_url(&"http://keycloak.internal/".parse().unwrap())
                .is_err()
        );
    }
}
