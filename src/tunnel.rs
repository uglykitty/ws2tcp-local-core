use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::TcpStream,
};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
    tungstenite::{
        Error as WsError, Message,
        handshake::client::Request,
        http::{HeaderName, HeaderValue, StatusCode},
    },
};
use tracing::{debug, info};

use crate::{
    gateway::Gateway,
    http_proxy::read_proxy_request,
    routing_rules::{RoutingRules, host_from_authority},
    session::GatewayAuth,
    socks5::{self, read_socks5_request},
    tls::insecure_websocket_connector,
};

#[derive(Debug, Clone)]
pub(crate) struct Config {
    pub(crate) gateway: Gateway,
    pub(crate) auth: GatewayAuth,
    pub(crate) buffer_size: usize,
    pub(crate) routing_rules: RoutingRules,
    pub(crate) insecure: bool,
    pub(crate) headers: Vec<(HeaderName, HeaderValue)>,
}

/// How to acknowledge a tunneled connection to the client, which differs by the
/// listening protocol: HTTP CONNECT and SOCKS5 both need an explicit reply before
/// bytes start flowing, while an ordinary HTTP proxy request has no such reply of
/// its own (the origin server's response passes straight through the tunnel).
enum ReplyStyle {
    HttpConnect,
    HttpPlain,
    Socks5,
}

impl ReplyStyle {
    async fn write_success(&self, client: &mut TcpStream) -> Result<()> {
        match self {
            Self::HttpConnect => client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .context("write CONNECT success response failed"),
            Self::HttpPlain => Ok(()),
            Self::Socks5 => client
                .write_all(&socks5::SUCCESS_REPLY)
                .await
                .context("write SOCKS5 success reply failed"),
        }
    }

    async fn write_error(&self, client: &mut TcpStream) {
        match self {
            Self::HttpConnect | Self::HttpPlain => {
                let _ = write_http_error(client, "502 Bad Gateway").await;
            }
            Self::Socks5 => {
                let _ = client.write_all(&socks5::GENERAL_FAILURE_REPLY).await;
            }
        }
    }
}

pub(crate) async fn handle_client(
    mut client: TcpStream,
    peer_addr: SocketAddr,
    config: Arc<Config>,
) -> Result<()> {
    let request = match read_proxy_request(&mut client).await {
        Ok(request) => request,
        Err(err) => {
            let _ = write_http_error(&mut client, "400 Bad Request").await;
            return Err(err);
        }
    };
    let authority = request.authority().to_owned();
    let host = host_from_authority(&authority)?;
    let should_proxy = config.routing_rules.should_proxy_host(host);
    let log_kind = request.log_kind();
    let reply = if request.is_connect() {
        ReplyStyle::HttpConnect
    } else {
        ReplyStyle::HttpPlain
    };
    let initial_client_bytes = request.initial_client_bytes();

    if !should_proxy {
        return handle_direct(
            client,
            peer_addr,
            authority,
            initial_client_bytes,
            log_kind,
            reply,
        )
        .await;
    }

    handle_gateway(
        client,
        peer_addr,
        authority,
        initial_client_bytes,
        log_kind,
        reply,
        config,
    )
    .await
}

pub(crate) async fn handle_socks_client(
    mut client: TcpStream,
    peer_addr: SocketAddr,
    config: Arc<Config>,
) -> Result<()> {
    let request = match read_socks5_request(&mut client).await {
        Ok(request) => request,
        Err(err) => {
            let _ = client.write_all(&socks5::GENERAL_FAILURE_REPLY).await;
            return Err(err);
        }
    };
    let host = host_from_authority(&request.authority)?;
    let should_proxy = config.routing_rules.should_proxy_host(host);

    if !should_proxy {
        return handle_direct(
            client,
            peer_addr,
            request.authority,
            Vec::new(),
            "socks5",
            ReplyStyle::Socks5,
        )
        .await;
    }

    handle_gateway(
        client,
        peer_addr,
        request.authority,
        Vec::new(),
        "socks5",
        ReplyStyle::Socks5,
        config,
    )
    .await
}

/// Builds the websocket handshake request sent to the gateway: the `Authorization` header (when
/// there are credentials) plus the caller-supplied custom headers.
pub(crate) fn build_gateway_request(
    ws_url: &str,
    authorization: Option<&str>,
    headers: &[(HeaderName, HeaderValue)],
) -> Result<Request> {
    let mut ws_request = ws_url
        .into_client_request()
        .with_context(|| format!("failed to build websocket request for {ws_url}"))?;
    if let Some(authorization) = authorization {
        let mut authorization: HeaderValue = authorization
            .parse()
            .context("failed to build authorization header")?;
        authorization.set_sensitive(true);
        ws_request
            .headers_mut()
            .insert("authorization", authorization);
    }

    for (name, value) in headers {
        ws_request.headers_mut().insert(name.clone(), value.clone());
    }

    Ok(ws_request)
}

pub(crate) fn gateway_connector(insecure: bool) -> Option<Connector> {
    insecure.then(insecure_websocket_connector)
}

/// Opens the websocket tunnel to the gateway.
///
/// When the gateway refuses an access token (it restarted, or the login was revoked), the token is
/// renewed and the request is tried once more.
async fn connect_gateway(
    config: &Config,
    ws_url: &str,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>> {
    let mut renewed = false;
    loop {
        let authorization = config.auth.authorization().await?;
        let request = build_gateway_request(ws_url, authorization.as_deref(), &config.headers)?;
        let connector = gateway_connector(config.insecure);
        match connect_async_tls_with_config(request, None, false, connector).await {
            Ok((websocket, _)) => return Ok(websocket),
            Err(WsError::Http(response))
                if response.status() == StatusCode::UNAUTHORIZED
                    && !renewed
                    && config.auth.can_renew() =>
            {
                renewed = true;
                debug!("gateway rejected the access token; renewing it");
                config.auth.rejected(authorization.as_deref()).await;
            }
            Err(err) => {
                return Err(err).with_context(|| format!("failed to connect gateway {ws_url}"));
            }
        }
    }
}

async fn handle_gateway(
    mut client: TcpStream,
    peer_addr: SocketAddr,
    authority: String,
    initial_client_bytes: Vec<u8>,
    log_kind: &'static str,
    reply: ReplyStyle,
    config: Arc<Config>,
) -> Result<()> {
    let ws_url = config.gateway.target_url(&authority);

    info!(%peer_addr, target = %authority, gateway = %ws_url, kind = log_kind, "proxying request");

    let websocket = match connect_gateway(&config, &ws_url).await {
        Ok(websocket) => websocket,
        Err(err) => {
            reply.write_error(&mut client).await;
            return Err(err);
        }
    };

    reply.write_success(&mut client).await?;

    proxy(client, websocket, initial_client_bytes, config.buffer_size).await
}

async fn handle_direct(
    mut client: TcpStream,
    peer_addr: SocketAddr,
    authority: String,
    initial_client_bytes: Vec<u8>,
    log_kind: &'static str,
    reply: ReplyStyle,
) -> Result<()> {
    info!(%peer_addr, target = %authority, kind = log_kind, "direct request");

    let mut upstream = match TcpStream::connect(&authority).await {
        Ok(upstream) => upstream,
        Err(err) => {
            reply.write_error(&mut client).await;
            return Err(err).with_context(|| format!("failed to connect target {authority}"));
        }
    };

    reply.write_success(&mut client).await?;

    if !initial_client_bytes.is_empty() {
        upstream
            .write_all(&initial_client_bytes)
            .await
            .context("write buffered client bytes to direct upstream failed")?;
    }

    copy_bidirectional(&mut client, &mut upstream)
        .await
        .context("direct TCP proxy failed")?;

    Ok(())
}

async fn write_http_error(client: &mut TcpStream, status: &str) -> Result<()> {
    let response = format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    client
        .write_all(response.as_bytes())
        .await
        .context("write HTTP error response failed")
}

async fn proxy(
    client: TcpStream,
    websocket: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    initial_client_bytes: Vec<u8>,
    buffer_size: usize,
) -> Result<()> {
    let (mut ws_writer, mut ws_reader) = websocket.split();
    let (mut client_reader, mut client_writer) = client.into_split();
    let mut client_buffer = vec![0_u8; buffer_size];

    if !initial_client_bytes.is_empty() {
        ws_writer
            .send(Message::Binary(initial_client_bytes.into()))
            .await
            .context("send buffered client bytes to websocket failed")?;
    }

    loop {
        tokio::select! {
            read_result = client_reader.read(&mut client_buffer) => {
                let n = read_result.context("read client failed")?;
                if n == 0 {
                    let _ = ws_writer.send(Message::Close(None)).await;
                    break;
                }

                ws_writer
                    .send(Message::Binary(client_buffer[..n].to_vec().into()))
                    .await
                    .context("send client bytes to websocket failed")?;
            }
            message = ws_reader.next() => {
                match message {
                    Some(Ok(Message::Binary(bytes))) => {
                        client_writer.write_all(&bytes).await.context("write websocket binary frame to client failed")?;
                    }
                    Some(Ok(Message::Text(text))) => {
                        client_writer.write_all(text.as_bytes()).await.context("write websocket text frame to client failed")?;
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        ws_writer.send(Message::Pong(payload)).await.context("send websocket pong failed")?;
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Frame(_))) => {}
                    Some(Ok(Message::Close(frame))) => {
                        debug!(?frame, "websocket closed");
                        client_writer.shutdown().await.context("shutdown client writer failed")?;
                        break;
                    }
                    Some(Err(err)) => return Err(err).context("read websocket frame failed"),
                    None => {
                        client_writer.shutdown().await.context("shutdown client writer failed")?;
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}
