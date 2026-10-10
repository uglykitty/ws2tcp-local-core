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
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::{Buf, Bytes};
use hpx_h3::{client::SendRequest, ext::Protocol, quinn as h3_quinn};
use serde::{Deserialize, Serialize};
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
    endpoint: quinn::Endpoint,
    // Tunnels currently open on this connection.
    tunnels: Arc<AtomicUsize>,
}

/// Decrements the tunnel count of a session when a tunnel's pump task ends.
struct TunnelGuard(Arc<AtomicUsize>);

impl Drop for TunnelGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// How tunnels to the gateway use HTTP/3. In a config file it is `"off"`, `"on"` or `"only"`;
/// `true` and `false` also work, as `"on"` and `"off"`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// TCP only.
    #[default]
    Off,
    /// HTTP/3 first, HTTP/1.1 over TCP when that fails.
    Preferred,
    /// HTTP/3 only: when it fails, the tunnel fails, with no TCP fallback.
    Only,
}

impl<'de> serde::Deserialize<'de> for Mode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Bool(bool),
            Name(String),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Bool(true) => Ok(Mode::Preferred),
            Raw::Bool(false) => Ok(Mode::Off),
            Raw::Name(name) => match name.as_str() {
                "off" => Ok(Mode::Off),
                "on" => Ok(Mode::Preferred),
                "only" => Ok(Mode::Only),
                _ => Err(serde::de::Error::custom(format!(
                    "http3 must be \"off\", \"on\" or \"only\", not {name:?}"
                ))),
            },
        }
    }
}

/// The HTTP/3 mode of the running proxy, which can be changed while it runs.
#[derive(Debug, Clone)]
pub(crate) struct Switch(std::sync::Arc<std::sync::Mutex<Mode>>);

impl Switch {
    pub(crate) fn new(mode: Mode) -> Self {
        Self(std::sync::Arc::new(std::sync::Mutex::new(mode)))
    }

    pub(crate) fn get(&self) -> Mode {
        *self.0.lock().unwrap()
    }

    pub(crate) fn set(&self, mode: Mode) {
        *self.0.lock().unwrap() = mode;
    }
}

/// One cached QUIC connection to the gateway, as [`snapshot`] reports it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http3ConnInfo {
    pub host: String,
    pub port: u16,
    pub local_addr: Option<String>,
    pub remote_addr: String,
    /// `established`, or `closed` for a connection that is about to be dropped from the cache.
    pub state: String,
    pub rtt_ms: u64,
    pub cwnd: u64,
    pub lost_packets: u64,
    pub udp_tx_bytes: u64,
    pub udp_rx_bytes: u64,
    pub active_tunnels: usize,
}

/// The HTTP/3 state of the proxy: the cached QUIC connections, and whether tunnels currently
/// skip HTTP/3 after a failure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Http3Snapshot {
    pub connections: Vec<Http3ConnInfo>,
    /// Seconds left of the period in which tunnels go straight to TCP, if one is running.
    pub tcp_fallback_secs_left: Option<u64>,
}

/// A snapshot of the cached HTTP/3 connections, for display (a `netstat` for QUIC: the UDP
/// socket alone says nothing, as every tunnel shares one connection).
pub async fn snapshot() -> Http3Snapshot {
    let mut connections: Vec<Http3ConnInfo> = SESSIONS
        .lock()
        .await
        .iter()
        .map(|((host, port, _), session)| {
            let stats = session.connection.stats();
            Http3ConnInfo {
                host: host.clone(),
                port: *port,
                local_addr: session
                    .endpoint
                    .local_addr()
                    .ok()
                    .map(|addr| addr.to_string()),
                remote_addr: session.connection.remote_address().to_string(),
                state: if session.connection.close_reason().is_none() {
                    "established"
                } else {
                    "closed"
                }
                .to_owned(),
                rtt_ms: u64::try_from(stats.path.rtt.as_millis()).unwrap_or(u64::MAX),
                cwnd: stats.path.cwnd,
                lost_packets: stats.path.lost_packets,
                udp_tx_bytes: stats.udp_tx.bytes,
                udp_rx_bytes: stats.udp_rx.bytes,
                active_tunnels: session.tunnels.load(Ordering::Relaxed),
            }
        })
        .collect();
    connections.sort_by(|a, b| (&a.host, a.port).cmp(&(&b.host, b.port)));
    let tcp_fallback_secs_left = (*FALLBACK_UNTIL.lock().unwrap())
        .and_then(|until| until.checked_duration_since(Instant::now()))
        .map(|left| left.as_secs() + 1);
    Http3Snapshot {
        connections,
        tcp_fallback_secs_left,
    }
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
///
/// With `only`, there is no fallback: a failure is an error, and no TCP period begins, so the
/// next tunnel tries HTTP/3 again.
pub(crate) async fn connect(
    request: &Request,
    insecure: bool,
    only: bool,
) -> Result<Option<DuplexStream>, WsError> {
    if !only && fallback_active() {
        return Ok(None);
    }
    match try_connect(request, insecure).await {
        Ok(stream) => Ok(Some(stream)),
        Err(WsError::Http(response)) if response.status() == StatusCode::UNAUTHORIZED => {
            Err(WsError::Http(response))
        }
        Err(err) if only => Err(err),
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
    let (mut requests, tunnels, cached) = session(&key).await?;
    let result = open_stream_in_time(&mut requests, &tunnels, request).await;
    if !cached || !matches!(&result, Err(err) if !matches!(err, WsError::Http(_))) {
        return result;
    }
    if let Err(err) = &result {
        debug!(error = %err, "HTTP/3 request on a cached connection failed; reconnecting");
    }
    SESSIONS.lock().await.remove(&key);
    let (mut requests, tunnels, _) = session(&key).await?;
    let result = open_stream_in_time(&mut requests, &tunnels, request).await;
    if matches!(&result, Err(err) if !matches!(err, WsError::Http(_))) {
        SESSIONS.lock().await.remove(&key);
    }
    result
}

async fn open_stream_in_time(
    requests: &mut Requests,
    tunnels: &Arc<AtomicUsize>,
    request: &Request,
) -> Result<DuplexStream, WsError> {
    match timeout(REQUEST_TIMEOUT, open_stream(requests, tunnels, request)).await {
        Ok(result) => result,
        Err(_) => Err(io_error("the gateway did not answer the websocket request")),
    }
}

/// The cached HTTP/3 connection to the gateway (established first if there is none), its tunnel
/// count, and whether it was already cached.
async fn session(key: &SessionKey) -> Result<(Requests, Arc<AtomicUsize>, bool), WsError> {
    let mut sessions = SESSIONS.lock().await;
    if let Some(session) = sessions.get(key) {
        if session.connection.close_reason().is_none() {
            return Ok((session.requests.clone(), session.tunnels.clone(), true));
        }
        sessions.remove(key);
    }
    let session = establish(&key.0, key.1, key.2).await?;
    let requests = session.requests.clone();
    let tunnels = session.tunnels.clone();
    sessions.insert(key.clone(), session);
    Ok((requests, tunnels, false))
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
        endpoint,
        tunnels: Arc::default(),
    })
}

/// Sends the extended CONNECT request for one tunnel and, once the gateway accepts it, turns the
/// request stream into a byte stream for the websocket frames.
async fn open_stream(
    requests: &mut Requests,
    tunnels: &Arc<AtomicUsize>,
    request: &Request,
) -> Result<DuplexStream, WsError> {
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
    tunnels.fetch_add(1, Ordering::Relaxed);
    let guard = TunnelGuard(tunnels.clone());
    tokio::spawn(async move {
        let _guard = guard;
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
