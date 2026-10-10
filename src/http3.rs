//! WebSocket over HTTP/3 (RFC 9220) to the gateway.
//!
//! The websocket handshake is an extended CONNECT request (`:protocol: websocket`) on a QUIC
//! stream, and once the gateway answers 200 the stream carries ordinary websocket frames. All
//! tunnels to one gateway share a single QUIC connection, so opening a tunnel costs no new
//! handshake and one stalled tunnel does not hold up the others.
//!
//! QUIC is UDP, which some networks drop, and not every gateway speaks RFC 9220. When HTTP/3
//! cannot be used, [`connect`] reports that, and the caller falls back to HTTP/1.1 over TCP.

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{LazyLock, Mutex},
    time::{Duration, Instant},
};

use bytes::{Buf, Bytes};
use hpx_h3::{client::SendRequest, ext::Protocol, quinn as h3_quinn};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex},
    net::lookup_host,
    sync::Mutex as AsyncMutex,
    time::timeout,
};
use tokio_tungstenite::tungstenite::{
    Error as WsError,
    handshake::client::Request,
    http::{HeaderName, Method, Response, StatusCode, header},
};
use tracing::{debug, warn};

use crate::tls::http3_client_config;

const QUIC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);
/// How long the gateway has to answer the websocket request. A cached connection whose gateway
/// has gone away stays "open" until QUIC's idle timeout, and shows up as a request that never
/// gets an answer.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// After HTTP/3 fails, tunnels go straight to TCP for this long instead of each paying the
/// handshake timeout again.
const FALLBACK_PERIOD: Duration = Duration::from_secs(60);
const PUMP_BUFFER: usize = 16 * 1024;
const STREAM_BUFFER: usize = 64 * 1024;

type Requests = SendRequest<h3_quinn::OpenStreams, Bytes>;

struct Session {
    requests: Requests,
    connection: quinn::Connection,
    // Keeps the UDP socket alive for as long as the session is cached.
    _endpoint: quinn::Endpoint,
}

type SessionKey = (String, u16, bool);

static SESSIONS: LazyLock<AsyncMutex<HashMap<SessionKey, Session>>> =
    LazyLock::new(Default::default);
static FALLBACK_UNTIL: Mutex<Option<Instant>> = Mutex::new(None);

/// Forgets the cached HTTP/3 connection (and any TCP fallback period), so the next tunnel
/// resolves the gateway again and dials a fresh QUIC connection. Tunnels already running keep
/// their streams, and the old connection closes by itself once they are done.
pub async fn reset_sessions() {
    SESSIONS.lock().await.clear();
    *FALLBACK_UNTIL.lock().unwrap() = None;
}

fn io_error(err: impl std::fmt::Display) -> WsError {
    WsError::Io(io::Error::other(err.to_string()))
}

fn fallback_active() -> bool {
    let mut until = FALLBACK_UNTIL.lock().unwrap();
    match *until {
        Some(instant) if instant > Instant::now() => true,
        Some(_) => {
            *until = None;
            false
        }
        None => false,
    }
}

/// Opens the websocket tunnel over HTTP/3, as the byte stream that carries the websocket frames
/// (the handshake is done). `Ok(None)` means HTTP/3 is not usable right now and
/// the caller should connect over TCP. The one error returned is the gateway refusing the
/// credentials (401), which a TCP connection would only repeat, and which the caller handles by
/// renewing its token.
pub(crate) async fn connect(
    request: &Request,
    insecure: bool,
) -> Result<Option<DuplexStream>, WsError> {
    if fallback_active() {
        return Ok(None);
    }
    match try_connect(request, insecure).await {
        Ok(stream) => Ok(Some(stream)),
        Err(WsError::Http(response)) if response.status() == StatusCode::UNAUTHORIZED => {
            Err(WsError::Http(response))
        }
        Err(err) => {
            warn!(
                error = %err,
                "HTTP/3 to the gateway failed; using HTTP/1.1 over TCP for the next {} seconds",
                FALLBACK_PERIOD.as_secs()
            );
            *FALLBACK_UNTIL.lock().unwrap() = Some(Instant::now() + FALLBACK_PERIOD);
            Ok(None)
        }
    }
}

async fn try_connect(request: &Request, insecure: bool) -> Result<DuplexStream, WsError> {
    let uri = request.uri();
    let host = uri
        .host()
        .ok_or_else(|| io_error("gateway URL has no host"))?;
    let port = uri.port_u16().unwrap_or(443);
    let key = (host.to_owned(), port, insecure);

    // A cached connection may have been closed by the gateway since it was last used; the
    // request is then repeated once on a new connection.
    let (mut requests, cached) = session(&key).await?;
    let result = open_stream_in_time(&mut requests, request).await;
    if !cached || !matches!(&result, Err(err) if !matches!(err, WsError::Http(_))) {
        return result;
    }
    if let Err(err) = &result {
        debug!(error = %err, "HTTP/3 request on a cached connection failed; reconnecting");
    }
    SESSIONS.lock().await.remove(&key);
    let (mut requests, _) = session(&key).await?;
    let result = open_stream_in_time(&mut requests, request).await;
    if matches!(&result, Err(err) if !matches!(err, WsError::Http(_))) {
        SESSIONS.lock().await.remove(&key);
    }
    result
}

async fn open_stream_in_time(
    requests: &mut Requests,
    request: &Request,
) -> Result<DuplexStream, WsError> {
    match timeout(REQUEST_TIMEOUT, open_stream(requests, request)).await {
        Ok(result) => result,
        Err(_) => Err(io_error("the gateway did not answer the websocket request")),
    }
}

/// The cached HTTP/3 connection to the gateway (established first if there is none), and whether
/// it was already cached.
async fn session(key: &SessionKey) -> Result<(Requests, bool), WsError> {
    let mut sessions = SESSIONS.lock().await;
    if let Some(session) = sessions.get(key) {
        if session.connection.close_reason().is_none() {
            return Ok((session.requests.clone(), true));
        }
        sessions.remove(key);
    }
    let session = establish(&key.0, key.1, key.2).await?;
    let requests = session.requests.clone();
    sessions.insert(key.clone(), session);
    Ok((requests, false))
}

async fn establish(host: &str, port: u16, insecure: bool) -> Result<Session, WsError> {
    let addrs: Vec<SocketAddr> = lookup_host((host, port))
        .await
        .map_err(WsError::Io)?
        .collect();
    let mut last_error = io_error(format!("{host} did not resolve to any address"));
    for addr in addrs {
        match timeout(QUIC_HANDSHAKE_TIMEOUT, connect_quic(addr, host, insecure)).await {
            Ok(Ok(session)) => return Ok(session),
            Ok(Err(err)) => last_error = err,
            Err(_) => last_error = io_error(format!("QUIC handshake with {addr} timed out")),
        }
    }
    Err(last_error)
}

async fn connect_quic(addr: SocketAddr, host: &str, insecure: bool) -> Result<Session, WsError> {
    let bind: SocketAddr = if addr.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        ([0_u16; 8], 0).into()
    };
    let mut endpoint = quinn::Endpoint::client(bind).map_err(WsError::Io)?;
    endpoint.set_default_client_config(http3_client_config(insecure).map_err(io_error)?);
    let connection = endpoint
        .connect(addr, host)
        .map_err(io_error)?
        .await
        .map_err(io_error)?;

    let (mut driver, requests) = hpx_h3::client::builder()
        .enable_extended_connect(true)
        .build(h3_quinn::Connection::new(connection.clone()))
        .await
        .map_err(io_error)?;
    // The driver runs the connection's control streams; it finishes when the connection closes.
    tokio::spawn(async move {
        let err = driver.wait_idle().await;
        debug!(error = %err, "HTTP/3 connection to the gateway closed");
    });
    debug!(%addr, "HTTP/3 connection to the gateway established");

    Ok(Session {
        requests,
        connection,
        _endpoint: endpoint,
    })
}

/// Sends the extended CONNECT request for one tunnel and, once the gateway accepts it, turns the
/// request stream into a byte stream for the websocket frames.
async fn open_stream(requests: &mut Requests, request: &Request) -> Result<DuplexStream, WsError> {
    let uri = request.uri();
    let authority = uri
        .authority()
        .ok_or_else(|| io_error("gateway URL has no authority"))?;
    let path = uri.path_and_query().map_or("/", |path| path.as_str());

    // RFC 9220 drops the HTTP/1.1 upgrade mechanics; everything else (authorization, custom
    // headers, `Sec-WebSocket-Version`) carries over.
    let skipped: [HeaderName; 5] = [
        header::HOST,
        header::CONNECTION,
        header::UPGRADE,
        header::SEC_WEBSOCKET_KEY,
        header::CONTENT_LENGTH,
    ];
    let mut builder = tokio_tungstenite::tungstenite::http::Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://{authority}{path}"))
        .extension(Protocol::WEBSOCKET);
    for (name, value) in request.headers() {
        if !skipped.contains(name) {
            builder = builder.header(name, value);
        }
    }
    let connect_request = builder.body(()).map_err(io_error)?;

    let mut stream = requests
        .send_request(connect_request)
        .await
        .map_err(io_error)?;
    let response = stream.recv_response().await.map_err(io_error)?;
    if response.status() != StatusCode::OK {
        let rejection = Response::builder()
            .status(response.status())
            .body(None)
            .map_err(io_error)?;
        return Err(WsError::Http(rejection));
    }

    let (mut send, mut recv) = stream.split();
    let (websocket_side, pump_side) = duplex(STREAM_BUFFER);
    let (mut from_websocket, mut to_websocket) = tokio::io::split(pump_side);
    tokio::spawn(async move {
        while let Ok(Some(mut data)) = recv.recv_data().await {
            while data.has_remaining() {
                let chunk = data.chunk();
                let len = chunk.len();
                if to_websocket.write_all(chunk).await.is_err() {
                    return;
                }
                data.advance(len);
            }
        }
        let _ = to_websocket.shutdown().await;
    });
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; PUMP_BUFFER];
        loop {
            match from_websocket.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if send
                        .send_data(Bytes::copy_from_slice(&buffer[..n]))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        }
        let _ = send.finish().await;
    });

    Ok(websocket_side)
}
