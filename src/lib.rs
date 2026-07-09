use anyhow::{Result, anyhow};

mod auth;
mod gateway;
mod http_proxy;
mod routing_rules;
pub mod service;
pub mod settings;
mod tls;
mod tunnel;

pub use service::run_proxy;
pub use settings::{
    DEFAULT_BUFFER_SIZE, DEFAULT_LISTEN, DEFAULT_RULE_REFRESH_INTERVAL_SECS, ProxyMode, Settings,
    SettingsOverrides,
};

pub fn init_logging(log_level: Option<&str>) -> Result<()> {
    let filter = match log_level {
        Some(filter) => filter.to_owned(),
        None => std::env::var("RUST_LOG").unwrap_or_else(|_| "ws2tcp_local=info".to_owned()),
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init()
        .or_else(|err| {
            if err
                .to_string()
                .contains("global default trace dispatcher has already been set")
            {
                Ok(())
            } else {
                Err(anyhow!("failed to initialize logging: {err}"))
            }
        })
}
