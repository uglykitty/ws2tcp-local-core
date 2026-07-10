use std::{future::Future, pin::Pin, sync::Arc};

use anyhow::{Result, anyhow};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::{
    auth::remote_basic_auth,
    gateway::Gateway,
    routing_rules::RoutingRules,
    settings::Settings,
    tunnel::{Config, handle_client},
};

pub async fn run_proxy(settings: Settings, shutdown: impl Future<Output = ()>) -> Result<()> {
    let (_mode_updates_tx, mode_updates_rx) = mpsc::unbounded_channel();
    run_proxy_with_mode_updates(settings, shutdown, mode_updates_rx).await
}

pub async fn run_proxy_with_mode_updates(
    settings: Settings,
    shutdown: impl Future<Output = ()>,
    mut mode_updates: mpsc::UnboundedReceiver<crate::ProxyMode>,
) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let routing_rules = RoutingRules::load(
        settings.proxy_mode,
        settings.custom_domain_rules.as_deref(),
        settings.rule_refresh_interval,
    )
    .await;

    let config = Arc::new(Config {
        gateway: Gateway::parse(&settings.gateway)?,
        basic_auth: remote_basic_auth(settings.basic_auth)?,
        buffer_size: settings.buffer_size,
        routing_rules,
        verify_server_certificate: settings.verify_server_certificate,
    });
    let dynamic_routing_rules = config.routing_rules.clone();
    tokio::spawn(async move {
        while let Some(mode) = mode_updates.recv().await {
            dynamic_routing_rules.set_mode(mode);
        }
    });
    let listener = TcpListener::bind(settings.listen)
        .await
        .map_err(|err| anyhow!("failed to bind {}: {err}", settings.listen))?;
    let listen_addr = listener.local_addr().unwrap_or(settings.listen);

    info!(
        listen = %listen_addr,
        gateway = %config.gateway.base(),
        verify_server_certificate = config.verify_server_certificate,
        rule_refresh_interval_secs = settings.rule_refresh_interval.as_secs(),
        routing_rules = %config.routing_rules,
        routing_rules_detail = %config.routing_rules.describe(),
        "listening"
    );
    if !config.verify_server_certificate {
        warn!(
            "remote gateway TLS server certificate verification is disabled; use --verify-server-certificate or verify_server_certificate = true to enable it"
        );
    }

    let mut shutdown = pin_shutdown(shutdown);

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, peer_addr) = accept_result
                    .map_err(|err| anyhow!("accept failed: {err}"))?;
                let config = Arc::clone(&config);

                tokio::spawn(async move {
                    if let Err(err) = handle_client(stream, peer_addr, config).await {
                        warn!(%peer_addr, error = %format_args!("{err:#}"), "connection closed with error");
                    }
                });
            }
            _ = &mut shutdown => {
                info!("shutdown requested");
                return Ok(());
            }
        }
    }
}

fn pin_shutdown<F>(shutdown: F) -> Pin<Box<F>>
where
    F: Future<Output = ()>,
{
    Box::pin(shutdown)
}
