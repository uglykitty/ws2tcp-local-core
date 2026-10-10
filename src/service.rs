use std::{future::Future, net::SocketAddr, pin::Pin, sync::Arc};

use anyhow::{Result, anyhow};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::{
    auth::remote_basic_auth,
    gateway::Gateway,
    gateway_check::check_gateway,
    http3::Mode as Http3Mode,
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
    let upstream_proxy = settings.upstream_proxy.map(Arc::new);
    if let Some(upstream_proxy) = &upstream_proxy {
        info!(upstream_proxy = %upstream_proxy, "all outgoing connections go through an upstream proxy");
    }
    let http3 = if settings.http3_only {
        // Nothing to fall back to: an unusable setup is an error, not a warning.
        if let Some(reason) = http3_unusable(&gateway, upstream_proxy.is_some()) {
            return Err(anyhow!("--http3-only cannot be used: {reason}"));
        }
        Http3Mode::Only
    } else if settings.http3 {
        match http3_unusable(&gateway, upstream_proxy.is_some()) {
            Some(reason) => {
                warn!("HTTP/3 is ignored because {reason}");
                Http3Mode::Off
            }
            None => Http3Mode::Preferred,
        }
    } else {
        Http3Mode::Off
    };
    let auth = match (settings.auth_mode, remote_basic_auth(settings.basic_auth)?) {
        // Authentication is not enabled: there is nothing to log in with, or to check credentials
        // against, so nothing is sent at startup.
        (_, None) => GatewayAuth::None,
        // No health check: the token login is the check.
        (AuthMode::Token, Some(basic_auth)) => {
            GatewayAuth::login(
                &gateway,
                basic_auth,
                settings.insecure,
                upstream_proxy.as_deref(),
                &settings.headers,
            )
            .await?
        }
        (AuthMode::Basic, Some(basic_auth)) => {
            check_gateway(
                &gateway,
                Some(&basic_auth),
                settings.insecure,
                http3,
                upstream_proxy.as_deref(),
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
        upstream_proxy.as_deref(),
    )
    .await?;

    let config = Arc::new(Config {
        gateway,
        auth,
        buffer_size: settings.buffer_size,
        routing_rules,
        insecure: settings.insecure,
        http3,
        upstream_proxy,
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
        http3 = ?config.http3,
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

/// Why `--http3` cannot apply, if it cannot: QUIC needs a `wss` gateway and a direct path to it.
fn http3_unusable(gateway: &Gateway, has_upstream_proxy: bool) -> Option<&'static str> {
    if !gateway.base().starts_with("wss://") {
        Some("the gateway is not a wss:// URL")
    } else if has_upstream_proxy {
        Some("an upstream proxy is configured, and QUIC cannot pass through one")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::SettingsOverrides;

    use super::*;

    async fn run_with(gateway: &str, upstream_proxy: Option<&str>) -> Result<()> {
        let settings = Settings::resolve(SettingsOverrides {
            gateway: Some(gateway.to_owned()),
            http3_only: true,
            upstream_proxy: upstream_proxy.map(str::to_owned),
            ..Default::default()
        })?;
        run_proxy(settings, std::future::pending()).await
    }

    #[tokio::test]
    async fn http3_only_is_refused_where_http3_cannot_work() {
        let err = run_with("ws://127.0.0.1:1", None).await.unwrap_err();
        assert!(format!("{err:#}").contains("--http3-only"), "{err:#}");
        assert!(format!("{err:#}").contains("wss://"), "{err:#}");

        let err = run_with("wss://example.com", Some("socks5h://127.0.0.1:1"))
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("upstream proxy"), "{err:#}");
    }
}
