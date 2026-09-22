use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, anyhow};
use futures_util::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpStream, UdpSocket},
    sync::mpsc,
    time::{Duration, timeout},
};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, client_async_tls_with_config,
    connect_async_tls_with_config,
    tungstenite::{
        Error as WsError, Message,
        error::UrlError,
        handshake::client::Request,
        http::{HeaderName, HeaderValue, StatusCode},
    },
};
use tracing::{debug, info};

use crate::{
    gateway::Gateway,
    http_proxy::read_proxy_request,
    routing_rules::{RoutingRules, host_from_authority, split_authority},
    session::GatewayAuth,
    socks5::{self, Socks5Command, read_socks5_request},
    tls::insecure_websocket_connector,
    upstream::UpstreamProxy,
};

/// How long a UDP ASSOCIATE session (the whole association, or one of its per-destination
/// tunnels) may sit idle before it is torn down. UDP has no close signal, so something has
/// to reclaim sessions nobody is using any more; the router applies the same default to its
/// end of each `/udp:` tunnel.
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Large enough for the maximum possible UDP payload (65507 bytes over IPv4/IPv6).
const UDP_DATAGRAM_BUFFER: usize = 65536;

#[derive(Debug, Clone)]
pub(crate) struct Config {
    pub(crate) gateway: Gateway,
    pub(crate) auth: GatewayAuth,
    pub(crate) buffer_size: usize,
    pub(crate) routing_rules: RoutingRules,
    pub(crate) insecure: bool,
    pub(crate) upstream_proxy: Option<Arc<UpstreamProxy>>,
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
            config.upstream_proxy.as_deref(),
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
    let command = match read_socks5_request(&mut client).await {
        Ok(command) => command,
        Err(err) => {
            let _ = client.write_all(&socks5::GENERAL_FAILURE_REPLY).await;
            return Err(err);
        }
    };

    let request = match command {
        Socks5Command::Connect(request) => request,
        Socks5Command::UdpAssociate => {
            return handle_socks_udp_associate(client, peer_addr, config).await;
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
            config.upstream_proxy.as_deref(),
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

/// Serves a SOCKS5 UDP ASSOCIATE session (RFC 1928 §7): a local UDP relay socket is opened
/// and its address handed back to the client, which then exchanges SOCKS5-framed UDP
/// datagrams with it for as long as `client` (the control connection) stays open. Each
/// distinct destination seen in those datagrams gets its own tunnel — through the gateway
/// when the routing rules say so, connected directly otherwise — mirroring how `/tcp:` and
/// direct connections are chosen for CONNECT requests.
async fn handle_socks_udp_associate(
    mut client: TcpStream,
    peer_addr: SocketAddr,
    config: Arc<Config>,
) -> Result<()> {
    let bind_addr: SocketAddr = if peer_addr.is_ipv6() {
        "[::1]:0"
    } else {
        "127.0.0.1:0"
    }
    .parse()
    .expect("hardcoded address is valid");

    let relay_socket = match UdpSocket::bind(bind_addr).await {
        Ok(socket) => socket,
        Err(err) => {
            let _ = client.write_all(&socks5::GENERAL_FAILURE_REPLY).await;
            return Err(err).context("failed to bind local UDP relay socket");
        }
    };
    let relay_addr = relay_socket
        .local_addr()
        .context("failed to read local UDP relay socket address")?;
    let relay_socket = Arc::new(relay_socket);

    client
        .write_all(&socks5::udp_associate_reply(relay_addr))
        .await
        .context("write SOCKS5 UDP ASSOCIATE reply failed")?;

    info!(%peer_addr, relay = %relay_addr, "accepted SOCKS5 UDP ASSOCIATE");

    // Senders feeding each destination's tunnel task, keyed by "host:port". Dropping a
    // sender (when this function returns) ends its task's `recv()` loop.
    let mut targets: HashMap<String, mpsc::Sender<Vec<u8>>> = HashMap::new();
    // The first datagram's source pins the association to that client, as recommended by
    // RFC 1928 §7; datagrams from elsewhere are ignored rather than accepted as a hijack.
    let mut client_addr: Option<SocketAddr> = None;
    let mut recv_buffer = vec![0_u8; UDP_DATAGRAM_BUFFER];
    let mut control_buffer = [0_u8; 1];

    loop {
        tokio::select! {
            // The control connection has no more requests to send; reading it here only
            // detects the client closing it, which is when RFC 1928 says the association
            // ends.
            read_result = client.read(&mut control_buffer) => {
                match read_result {
                    Ok(0) => {
                        debug!(%peer_addr, "SOCKS5 UDP ASSOCIATE control connection closed");
                        break;
                    }
                    Ok(_) => {} // Not part of the protocol; ignore.
                    Err(err) => {
                        debug!(%peer_addr, error = %err, "SOCKS5 UDP ASSOCIATE control connection error");
                        break;
                    }
                }
            }
            recv_result = timeout(UDP_IDLE_TIMEOUT, relay_socket.recv_from(&mut recv_buffer)) => {
                let Ok(recv_result) = recv_result else {
                    debug!(%peer_addr, "SOCKS5 UDP ASSOCIATE idle timeout reached");
                    break;
                };
                let (n, from) = recv_result.context("read UDP datagram from client failed")?;

                match client_addr {
                    Some(expected) if expected != from => continue,
                    Some(_) => {}
                    None => client_addr = Some(from),
                }

                let (host, port, payload) = match socks5::parse_udp_datagram(&recv_buffer[..n]) {
                    Ok(parsed) => parsed,
                    Err(err) => {
                        debug!(%peer_addr, error = %err, "dropping malformed SOCKS5 UDP datagram");
                        continue;
                    }
                };

                let key = format!("{host}:{port}");
                let sender = if let Some(sender) = targets.get(&key) {
                    sender.clone()
                } else {
                    let (tx, rx) = mpsc::channel(32);
                    targets.insert(key, tx.clone());
                    tokio::spawn(run_udp_target(
                        Arc::clone(&config),
                        host,
                        port,
                        rx,
                        Arc::clone(&relay_socket),
                        from,
                    ));
                    tx
                };
                // The target task exits (and its channel closes) once it is idle for too
                // long; a send racing that shutdown is simply dropped, same as one more UDP
                // packet arriving just as the real thing would time out.
                let _ = sender.send(payload.to_vec()).await;
            }
        }
    }

    Ok(())
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

/// Performs the websocket handshake of `request`, connecting through the upstream proxy when there
/// is one. The TLS handshake of a `wss` gateway runs inside the tunnel the proxy sets up, so the
/// proxy sees only the gateway's address.
pub(crate) async fn connect_websocket(
    request: Request,
    insecure: bool,
    upstream_proxy: Option<&UpstreamProxy>,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, WsError> {
    let connector = gateway_connector(insecure);
    let Some(upstream_proxy) = upstream_proxy else {
        return connect_async_tls_with_config(request, None, false, connector)
            .await
            .map(|(websocket, _)| websocket);
    };

    let uri = request.uri();
    let host = uri.host().ok_or(WsError::Url(UrlError::NoHostName))?;
    let port = uri
        .port_u16()
        .unwrap_or(if uri.scheme_str() == Some("wss") {
            443
        } else {
            80
        });
    let stream = upstream_proxy
        .connect(host, port)
        .await
        .map_err(WsError::Io)?;
    client_async_tls_with_config(request, stream, None, connector)
        .await
        .map(|(websocket, _)| websocket)
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
        match connect_websocket(request, config.insecure, config.upstream_proxy.as_deref()).await {
            Ok(websocket) => return Ok(websocket),
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

/// Serves a request that no routing rule sends to the gateway: it connects to the target itself,
/// through the upstream proxy when there is one, so that no connection leaves the machine
/// around it.
async fn handle_direct(
    mut client: TcpStream,
    peer_addr: SocketAddr,
    authority: String,
    initial_client_bytes: Vec<u8>,
    log_kind: &'static str,
    reply: ReplyStyle,
    upstream_proxy: Option<&UpstreamProxy>,
) -> Result<()> {
    info!(
        %peer_addr,
        target = %authority,
        kind = log_kind,
        via_upstream_proxy = upstream_proxy.is_some(),
        "direct request"
    );

    let connected = match upstream_proxy {
        Some(upstream_proxy) => match split_authority(&authority) {
            Ok((host, port)) => upstream_proxy.connect(host, port).await,
            Err(err) => Err(std::io::Error::other(err)),
        },
        None => TcpStream::connect(&authority).await,
    };
    let mut upstream = match connected {
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

/// Owns one destination's UDP traffic within a SOCKS5 UDP ASSOCIATE session: everything
/// `inbound` yields is one datagram to `host:port`, and everything that comes back is
/// wrapped as a SOCKS5 UDP response datagram and sent to `client_addr` on `relay_socket`.
/// Ends, dropping the tunnel, after `UDP_IDLE_TIMEOUT` passes with nothing in either
/// direction, or when `inbound` closes (the association ended).
async fn run_udp_target(
    config: Arc<Config>,
    host: String,
    port: u16,
    inbound: mpsc::Receiver<Vec<u8>>,
    relay_socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
) {
    let authority = format!("{host}:{port}");
    let should_proxy = config.routing_rules.should_proxy_host(&host);

    let result = if should_proxy {
        run_udp_target_gateway(&config, &host, port, &authority, inbound, &relay_socket, client_addr).await
    } else {
        run_udp_target_direct(&host, port, &authority, inbound, &relay_socket, client_addr).await
    };

    if let Err(err) = result {
        debug!(target = %authority, error = %format_args!("{err:#}"), "SOCKS5 UDP target session ended");
    }
}

/// Relays one destination's UDP datagrams through the gateway, over a `/udp:` tunnel
/// dedicated to it.
async fn run_udp_target_gateway(
    config: &Config,
    host: &str,
    port: u16,
    authority: &str,
    mut inbound: mpsc::Receiver<Vec<u8>>,
    relay_socket: &UdpSocket,
    client_addr: SocketAddr,
) -> Result<()> {
    let ws_url = config.gateway.target_url_udp(authority);
    info!(target = %authority, gateway = %ws_url, kind = "socks5-udp", "proxying UDP request");

    let websocket = connect_gateway(config, &ws_url).await?;
    let (mut ws_writer, mut ws_reader) = websocket.split();

    loop {
        tokio::select! {
            payload = timeout(UDP_IDLE_TIMEOUT, inbound.recv()) => {
                let Ok(payload) = payload else {
                    debug!(target = %authority, "UDP gateway tunnel idle timeout reached");
                    let _ = ws_writer.send(Message::Close(None)).await;
                    break;
                };
                let Some(payload) = payload else { break };
                ws_writer
                    .send(Message::Binary(payload.into()))
                    .await
                    .context("send udp payload to websocket failed")?;
            }
            message = timeout(UDP_IDLE_TIMEOUT, ws_reader.next()) => {
                let Ok(message) = message else {
                    debug!(target = %authority, "UDP gateway tunnel idle timeout reached");
                    let _ = ws_writer.send(Message::Close(None)).await;
                    break;
                };
                match message {
                    Some(Ok(Message::Binary(bytes))) => {
                        send_udp_datagram_to_client(relay_socket, host, port, &bytes, client_addr).await?;
                    }
                    Some(Ok(Message::Text(text))) => {
                        send_udp_datagram_to_client(relay_socket, host, port, text.as_bytes(), client_addr).await?;
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        ws_writer.send(Message::Pong(payload)).await.context("send websocket pong failed")?;
                    }
                    Some(Ok(Message::Pong(_) | Message::Frame(_))) => {}
                    Some(Ok(Message::Close(frame))) => {
                        debug!(?frame, target = %authority, "udp gateway tunnel websocket closed");
                        break;
                    }
                    Some(Err(err)) => return Err(err).context("read websocket frame failed"),
                    None => break,
                }
            }
        }
    }

    Ok(())
}

/// Relays one destination's UDP datagrams directly, without the gateway, through the
/// upstream proxy when one is configured for the token/control-plane connections. A UDP
/// upstream proxy is not something this codebase supports, so a direct UDP destination
/// always goes out from this machine's own network interface.
async fn run_udp_target_direct(
    host: &str,
    port: u16,
    authority: &str,
    mut inbound: mpsc::Receiver<Vec<u8>>,
    relay_socket: &UdpSocket,
    client_addr: SocketAddr,
) -> Result<()> {
    info!(target = %authority, kind = "socks5-udp", "direct UDP request");

    let resolved = tokio::net::lookup_host(authority)
        .await
        .with_context(|| format!("failed to resolve udp target {authority}"))?
        .next()
        .ok_or_else(|| anyhow!("udp target {authority} did not resolve"))?;
    let bind_addr = if resolved.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let upstream = UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind local UDP socket for {authority}"))?;
    upstream
        .connect(resolved)
        .await
        .with_context(|| format!("failed to connect udp socket to {authority}"))?;

    let mut upstream_buffer = vec![0_u8; UDP_DATAGRAM_BUFFER];

    loop {
        tokio::select! {
            payload = timeout(UDP_IDLE_TIMEOUT, inbound.recv()) => {
                let Ok(payload) = payload else {
                    debug!(target = %authority, "direct UDP session idle timeout reached");
                    break;
                };
                let Some(payload) = payload else { break };
                upstream.send(&payload).await.context("send udp payload to direct upstream failed")?;
            }
            read_result = timeout(UDP_IDLE_TIMEOUT, upstream.recv(&mut upstream_buffer)) => {
                let Ok(read_result) = read_result else {
                    debug!(target = %authority, "direct UDP session idle timeout reached");
                    break;
                };
                let n = read_result.context("read udp datagram from direct upstream failed")?;
                send_udp_datagram_to_client(relay_socket, host, port, &upstream_buffer[..n], client_addr).await?;
            }
        }
    }

    Ok(())
}

/// Wraps `payload` as a SOCKS5 UDP response datagram claiming to be from `host:port` and
/// sends it to the SOCKS5 client's address on the local relay socket.
async fn send_udp_datagram_to_client(
    relay_socket: &UdpSocket,
    host: &str,
    port: u16,
    payload: &[u8],
    client_addr: SocketAddr,
) -> Result<()> {
    let datagram = socks5::build_udp_datagram(host, port, payload);
    relay_socket
        .send_to(&datagram, client_addr)
        .await
        .context("send udp datagram to client failed")?;
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

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

    use super::*;

    const CONNECTED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

    /// Returns the end of a client connection that `handle_direct` serves, and the client's end.
    async fn client_connection() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (served, _) = listener.accept().await.unwrap();
        (served, client)
    }

    /// Accepts one connection, reads a `\r\n\r\n`-terminated header or, without one, four bytes
    /// and echoes back four bytes. Returns what it received first.
    async fn echo_once(mut stream: TcpStream, expect_connect: bool) -> String {
        let mut received = Vec::new();
        let mut byte = [0_u8; 1];
        if expect_connect {
            while !received.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                received.push(byte[0]);
            }
            stream.write_all(CONNECTED).await.unwrap();
        }
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).await.unwrap();
        stream.write_all(&payload).await.unwrap();
        String::from_utf8(received).unwrap()
    }

    #[tokio::test]
    async fn direct_requests_go_through_the_upstream_proxy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy =
            UpstreamProxy::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let fake_proxy = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            echo_once(stream, true).await
        });
        let (served, mut client) = client_connection().await;
        let peer_addr = client.local_addr().unwrap();
        let handler = tokio::spawn(async move {
            handle_direct(
                served,
                peer_addr,
                // Does not resolve: it can only be reached through the proxy.
                "target.invalid:9000".to_owned(),
                Vec::new(),
                "test",
                ReplyStyle::HttpConnect,
                Some(&proxy),
            )
            .await
        });

        let mut reply = vec![0_u8; CONNECTED.len()];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, CONNECTED);
        client.write_all(b"ping").await.unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
        drop(client);

        assert!(
            fake_proxy
                .await
                .unwrap()
                .starts_with("CONNECT target.invalid:9000 HTTP/1.1\r\n")
        );
        handler.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn direct_requests_fail_with_502_when_the_upstream_proxy_is_unusable() {
        let dead = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let proxy = UpstreamProxy::parse(&format!("socks5h://user:secret@{dead}")).unwrap();
        let (served, mut client) = client_connection().await;
        let peer_addr = client.local_addr().unwrap();

        let err = handle_direct(
            served,
            peer_addr,
            "example.com:443".to_owned(),
            Vec::new(),
            "test",
            ReplyStyle::HttpConnect,
            Some(&proxy),
        )
        .await
        .unwrap_err();

        let message = format!("{err:#}");
        assert!(message.contains(&format!("socks5h://{dead}")), "{message}");
        assert!(!message.contains("secret"), "{message}");
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 502"), "{response}");
    }

    #[tokio::test]
    async fn direct_requests_connect_to_the_target_without_an_upstream_proxy() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let authority = target.local_addr().unwrap().to_string();
        let fake_target = tokio::spawn(async move {
            let (stream, _) = target.accept().await.unwrap();
            echo_once(stream, false).await
        });
        let (served, mut client) = client_connection().await;
        let peer_addr = client.local_addr().unwrap();
        let handler = tokio::spawn(async move {
            handle_direct(
                served,
                peer_addr,
                authority,
                Vec::new(),
                "test",
                ReplyStyle::HttpConnect,
                None,
            )
            .await
        });

        let mut reply = vec![0_u8; CONNECTED.len()];
        client.read_exact(&mut reply).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
        drop(client);

        fake_target.await.unwrap();
        handler.await.unwrap().unwrap();
    }
}
