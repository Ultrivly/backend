use clap::{Args, ValueEnum};

#[derive(Args, Clone)]
pub struct DatabaseConfig {
    #[arg(
        help = "PostgreSQL connection URL",
        long,
        env = "DATABASE_URL",
        hide_env_values = true
    )]
    pub database_url: String,

    #[arg(
        help = "Maximum number of pooled database connections",
        long,
        env = "ULTRIVLY_DB_MAX_CONNECTIONS",
        default_value_t = 10
    )]
    pub db_max_connections: u32,

    #[arg(
        help = "Seconds to wait for a free database connection",
        long,
        env = "ULTRIVLY_DB_ACQUIRE_TIMEOUT_SECS",
        default_value_t = 5
    )]
    pub db_acquire_timeout_secs: u64,
}

#[derive(Args, Clone)]
pub struct StorageConfig {
    #[arg(
        help = "File storage: s3://bucket[/prefix], file:///absolute/path, or memory://",
        long,
        env = "ULTRIVLY_STORAGE_URL"
    )]
    pub storage_url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Deployment {
    #[value(name = "cloud")]
    Cloud,
    #[value(name = "self_hosted")]
    SelfHosted,
}

#[derive(Args, Clone)]
pub struct AuthConfig {
    #[arg(
        help = "Key for encrypting stored secrets (base64, 32 bytes); generate with `ultrivly secret-key`",
        long,
        env = "ULTRIVLY_SECRET_KEY",
        hide_env_values = true
    )]
    pub secret_key: String,

    #[arg(
        help = "cloud or self_hosted; controls a few security defaults",
        long,
        env = "ULTRIVLY_DEPLOYMENT",
        value_enum,
        default_value = "self_hosted"
    )]
    pub deployment: Deployment,

    #[arg(
        help = "Self-hosted only: hosts outbound requests may reach on private networks or plain http",
        long,
        env = "ULTRIVLY_NET_ALLOW",
        value_delimiter = ','
    )]
    pub net_allow: Vec<String>,

    #[arg(
        help = "Public base URL of this install, e.g. https://support.example.com",
        long,
        env = "ULTRIVLY_PUBLIC_URL"
    )]
    pub public_url: String,
}

#[derive(Args, Clone)]
pub struct MailConfig {
    #[arg(
        help = "smtps://user:pass@host:465, smtp://user:pass@host:587?tls=required, or log:// (development)",
        long,
        env = "ULTRIVLY_MAIL_URL",
        hide_env_values = true
    )]
    pub mail_url: String,

    #[arg(
        help = "Sender address for outgoing email",
        long,
        env = "ULTRIVLY_MAIL_FROM",
        default_value = "Ultrivly <no-reply@localhost>"
    )]
    pub mail_from: String,

    #[arg(
        help = "Secret that signs bounce and complaint events posted to /api/v1/mail/events; unset disables that endpoint",
        long,
        env = "ULTRIVLY_MAIL_EVENTS_SECRET",
        hide_env_values = true
    )]
    pub mail_events_secret: Option<String>,
}

#[derive(Args, Clone)]
pub struct HttpConfig {
    #[arg(
        help = "Address to listen on",
        long,
        env = "ULTRIVLY_BIND",
        default_value = "0.0.0.0:8080"
    )]
    pub bind: std::net::SocketAddr,

    #[arg(
        help = "Reverse proxies whose X-Forwarded-For entries are trusted",
        long,
        env = "ULTRIVLY_TRUSTED_PROXY_HOPS",
        default_value_t = 0
    )]
    pub trusted_proxy_hops: usize,

    #[arg(
        help = "Requests per minute allowed for one API key or session; 0 disables",
        long,
        env = "ULTRIVLY_RATE_LIMIT_PER_CALLER",
        default_value_t = 1200
    )]
    pub rate_limit_per_caller: u32,

    #[arg(
        help = "Requests per minute allowed from one client IP address; 0 disables",
        long,
        env = "ULTRIVLY_RATE_LIMIT_PER_IP",
        default_value_t = 3000
    )]
    pub rate_limit_per_ip: u32,
}

#[derive(Args, Clone)]
pub struct SocialConfig {
    #[arg(
        help = "Google sign-in client ID",
        long,
        env = "ULTRIVLY_GOOGLE_CLIENT_ID"
    )]
    pub google_client_id: Option<String>,

    #[arg(
        help = "Google sign-in client secret",
        long,
        env = "ULTRIVLY_GOOGLE_CLIENT_SECRET",
        hide_env_values = true
    )]
    pub google_client_secret: Option<String>,
}

#[derive(Args, Clone)]
pub struct MetricsConfig {
    #[arg(
        help = "Serve Prometheus metrics at /metrics on this address, e.g. 127.0.0.1:9090; keep it off the public network",
        long,
        env = "ULTRIVLY_METRICS_BIND"
    )]
    pub metrics_bind: Option<std::net::SocketAddr>,
}
