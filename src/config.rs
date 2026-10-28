use clap::{Args, ValueEnum};





#[derive(Args, Clone)]
pub struct DatabaseConfig {
    
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    pub database_url: String,

    
    #[arg(long, env = "ULTRIVLY_DB_MAX_CONNECTIONS", default_value_t = 10)]
    pub db_max_connections: u32,

    
    #[arg(long, env = "ULTRIVLY_DB_ACQUIRE_TIMEOUT_SECS", default_value_t = 5)]
    pub db_acquire_timeout_secs: u64,
}


#[derive(Args, Clone)]
pub struct StorageConfig {
    
    #[arg(long, env = "ULTRIVLY_STORAGE_URL")]
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
    
    
    #[arg(long, env = "ULTRIVLY_SECRET_KEY", hide_env_values = true)]
    pub secret_key: String,

    #[arg(
        long,
        env = "ULTRIVLY_DEPLOYMENT",
        value_enum,
        default_value = "self_hosted"
    )]
    pub deployment: Deployment,

    
    
    #[arg(long, env = "ULTRIVLY_NET_ALLOW", value_delimiter = ',')]
    pub net_allow: Vec<String>,

    
    
    #[arg(long, env = "ULTRIVLY_PUBLIC_URL")]
    pub public_url: String,
}


#[derive(Args, Clone)]
pub struct MailConfig {
    
    
    #[arg(long, env = "ULTRIVLY_MAIL_URL", hide_env_values = true)]
    pub mail_url: String,

    
    #[arg(
        long,
        env = "ULTRIVLY_MAIL_FROM",
        default_value = "Ultrivly <no-reply@localhost>"
    )]
    pub mail_from: String,
}


#[derive(Args, Clone)]
pub struct HttpConfig {
    #[arg(long, env = "ULTRIVLY_BIND", default_value = "0.0.0.0:8080")]
    pub bind: std::net::SocketAddr,

    
    
    
    #[arg(long, env = "ULTRIVLY_TRUSTED_PROXY_HOPS", default_value_t = 0)]
    pub trusted_proxy_hops: usize,
}


#[derive(Args, Clone)]
pub struct SocialConfig {
    #[arg(long, env = "ULTRIVLY_GOOGLE_CLIENT_ID")]
    pub google_client_id: Option<String>,

    #[arg(long, env = "ULTRIVLY_GOOGLE_CLIENT_SECRET", hide_env_values = true)]
    pub google_client_secret: Option<String>,
}
