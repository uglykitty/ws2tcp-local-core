use std::{future::Future, net::SocketAddr, pin::Pin, sync::Arc};

use anyhow::{Result, anyhow};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::{
    auth::remote_basic_auth,
    gateway::Gateway,
    gateway_check::check_gateway,
    routing_rules::RoutingRules,
    session::GatewayAuth,
    settings::{AuthMode, Settings},
    tunnel::{Config, handle_client, handle_socks_client},
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

    // Fail fast, before fetching routing rules or binding any port, when the gateway cannot be
    // used with the credentials (most importantly, when they are wrong). Token mode does that with
    // the login, basic mode with a health check.
    let gateway = Gateway::parse(&settings.gateway)?;
    let auth = match (settings.auth_mode, remote_basic_auth(settings.basic_auth)?) {
        // Authentication is not enabled: there is nothing to log in with, or to check credentials
        // against, so nothing is sent at startup.
        (_, None) => GatewayAuth::None,
        // No health check: the token login is the check.
        (AuthMode::Token, Some(basic_auth)) => {
            GatewayAuth::login(&gateway, basic_auth, settings.insecure, &settings.headers).await?
        }
        (AuthMode::Basic, Some(basic_auth)) => {
            check_gateway(
                &gateway,
                Some(&basic_auth),
                settings.insecure,
                &settings.headers,
            )
            .await?;
            info!(gateway = %gateway.base(), "gateway health check passed");
            warn!(
                "Basic Auth mode is kept for compatibility and will be phased out; use the \
                 token auth mode, which needs a ws2tcp-router with token authentication"
            );
            GatewayAuth::Basic(basic_auth)
        }
    };
    info!(gateway = %gateway.base(), auth = auth.describe(), "gateway authentication ready");
    let headers = settings.headers;

    let routing_rules = RoutingRules::load(
        settings.proxy_mode,
        settings.custom_domain_rules.as_deref(),
        settings.rule_refresh_interval,
    )
    .await;

    let config = Arc::new(Config {
        gateway,
        auth,
        buffer_size: settings.buffer_size,
        routing_rules,
        insecure: settings.insecure,
        headers,
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

    let socks_listener = match settings.socks_listen {
        Some(addr) => Some(
            TcpListener::bind(addr)
                .await
                .map_err(|err| anyhow!("failed to bind SOCKS5 listener {addr}: {err}"))?,
        ),
        None => None,
    };
    let socks_listen_addr = socks_listener.as_ref().map(|listener| {
        listener
            .local_addr()
            .unwrap_or_else(|_| settings.socks_listen.unwrap())
    });

    info!(
        listen = %listen_addr,
        socks_listen = %socks_listen_addr.map(|addr| addr.to_string()).unwrap_or_else(|| "disabled".to_owned()),
        gateway = %config.gateway.base(),
        insecure = config.insecure,
        rule_refresh_interval_secs = settings.rule_refresh_interval.as_secs(),
        routing_rules = %config.routing_rules,
        routing_rules_detail = %config.routing_rules.describe(),
        "listening"
    );
    if config.insecure {
        warn!(
            "remote gateway TLS server certificate verification is disabled because insecure mode is enabled"
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
            accept_result = accept_optional(&socks_listener), if socks_listener.is_some() => {
                let (stream, peer_addr) = accept_result
                    .map_err(|err| anyhow!("SOCKS5 accept failed: {err}"))?;
                let config = Arc::clone(&config);

                tokio::spawn(async move {
                    if let Err(err) = handle_socks_client(stream, peer_addr, config).await {
                        warn!(%peer_addr, error = %format_args!("{err:#}"), "SOCKS5 connection closed with error");
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

async fn accept_optional(
    listener: &Option<TcpListener>,
) -> std::io::Result<(TcpStream, SocketAddr)> {
    listener
        .as_ref()
        .expect("accept_optional is only polled when the listener is Some")
        .accept()
        .await
}

fn pin_shutdown<F>(shutdown: F) -> Pin<Box<F>>
where
    F: Future<Output = ()>,
{
    Box::pin(shutdown)
}
