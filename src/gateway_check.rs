use std::{fmt, io::ErrorKind, time::Duration};

use futures_util::StreamExt;
use tokio::time::timeout;
use tokio_tungstenite::{
    connect_async_tls_with_config,
    tungstenite::{
        Error as WsError, Message,
        http::{HeaderName, HeaderValue, StatusCode},
    },
};

use crate::{
    gateway::Gateway,
    tunnel::{build_gateway_request, gateway_connector},
};

const CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// Header on the health check response with the token the router hands out, and on every tunnel
/// request that follows. The router does not verify the token yet.
const TOKEN_HEADER: &str = "x-ws2tcp-token";

/// What a ws2tcp-router health check (`GET <gateway>/`) answers with as its first message.
const HEALTH_CHECK_MESSAGE_PREFIX: &str = "ok: ws2tcp-router";

/// What the gateway reported in a successful startup check.
#[derive(Debug)]
pub(crate) struct GatewayHealth {
    /// The token from the health check response, when the gateway sent one.
    pub(crate) token: Option<HeaderValue>,
}

/// Returns `headers` extended with the gateway `token` (when there is one), replacing any header
/// of the same name, so that it is sent on every tunnel request next to the Basic Auth header.
pub(crate) fn headers_with_token(
    mut headers: Vec<(HeaderName, HeaderValue)>,
    token: Option<HeaderValue>,
) -> Vec<(HeaderName, HeaderValue)> {
    if let Some(token) = token {
        let name = HeaderName::from_static(TOKEN_HEADER);
        headers.retain(|(existing, _)| *existing != name);
        headers.push((name, token));
    }
    headers
}

/// Why the startup check of the remote gateway failed. [`run_proxy`](crate::run_proxy) returns it
/// inside an [`anyhow::Error`]; use `downcast_ref` to tell an authentication failure (which the
/// user has to fix) from the gateway simply not being usable.
#[derive(Debug)]
pub enum GatewayCheckError {
    /// The gateway answered `401 Unauthorized`.
    Unauthorized {
        /// Whether Basic Auth credentials were configured for the request that was rejected.
        credentials_configured: bool,
    },
    /// The gateway could not be reached, timed out, or did not answer like a ws2tcp-router.
    Failed(String),
}

impl fmt::Display for GatewayCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized {
                credentials_configured: true,
            } => write!(
                f,
                "gateway rejected the Basic Auth credentials (401 Unauthorized); check \
                 --basic-auth or WS2TCP_LOCAL_BASIC_AUTH"
            ),
            Self::Unauthorized {
                credentials_configured: false,
            } => write!(
                f,
                "gateway requires Basic Auth (401 Unauthorized), but no credentials were \
                 configured; set --basic-auth or WS2TCP_LOCAL_BASIC_AUTH"
            ),
            Self::Failed(reason) => write!(f, "gateway health check failed: {reason}"),
        }
    }
}

impl std::error::Error for GatewayCheckError {}

/// Verifies the gateway before serving: performs a websocket handshake on the gateway root, with
/// the same credentials, custom headers and TLS settings as real tunnels, and expects the
/// ws2tcp-router health check message.
pub(crate) async fn check_gateway(
    gateway: &Gateway,
    basic_auth: Option<&str>,
    insecure: bool,
    headers: &[(HeaderName, HeaderValue)],
) -> Result<GatewayHealth, GatewayCheckError> {
    let url = gateway.health_check_url();
    let request = build_gateway_request(&url, basic_auth, headers)
        .map_err(|err| GatewayCheckError::Failed(format!("{err:#}")))?;

    let check = async {
        let (mut websocket, response) =
            connect_async_tls_with_config(request, None, false, gateway_connector(insecure))
                .await
                .map_err(|err| classify_connect_error(err, basic_auth.is_some()))?;
        let token = response
            .headers()
            .get(TOKEN_HEADER)
            .cloned()
            .map(|mut token| {
                // Keep the token out of `Debug` output (and so out of logs).
                token.set_sensitive(true);
                token
            });

        match websocket.next().await {
            Some(Ok(Message::Text(text))) if text.starts_with(HEALTH_CHECK_MESSAGE_PREFIX) => {
                Ok(GatewayHealth { token })
            }
            Some(Ok(other)) => Err(GatewayCheckError::Failed(format!(
                "unexpected reply from {url}: {other:?}"
            ))),
            Some(Err(err)) => Err(GatewayCheckError::Failed(format!("{err}"))),
            None => Err(GatewayCheckError::Failed(format!(
                "{url} closed the connection without a health check reply"
            ))),
        }
    };

    match timeout(CHECK_TIMEOUT, check).await {
        Ok(result) => result,
        Err(_) => Err(GatewayCheckError::Failed(format!(
            "no reply from {url} within {} seconds",
            CHECK_TIMEOUT.as_secs()
        ))),
    }
}

fn classify_connect_error(err: WsError, credentials_configured: bool) -> GatewayCheckError {
    match err {
        WsError::Http(response) if response.status() == StatusCode::UNAUTHORIZED => {
            GatewayCheckError::Unauthorized {
                credentials_configured,
            }
        }
        WsError::Http(response) => {
            GatewayCheckError::Failed(format!("gateway answered HTTP {}", response.status()))
        }
        err if ended_handshake(&err) => GatewayCheckError::Failed(format!(
            "{err} (the gateway ended the handshake; a ws2tcp-router without the `/` health \
             check does this)"
        )),
        err => GatewayCheckError::Failed(format!("{err}")),
    }
}

/// Whether the gateway accepted the connection but then cut the handshake short, as opposed to
/// being unreachable. A ws2tcp-router without the `/` health check drops such a request.
fn ended_handshake(err: &WsError) -> bool {
    match err {
        WsError::ConnectionClosed | WsError::AlreadyClosed | WsError::Protocol(_) => true,
        WsError::Io(io) => matches!(
            io.kind(),
            ErrorKind::ConnectionReset
                | ErrorKind::ConnectionAborted
                | ErrorKind::UnexpectedEof
                | ErrorKind::BrokenPipe
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;
    use tokio_tungstenite::{
        accept_hdr_async,
        tungstenite::handshake::server::{ErrorResponse, Request, Response},
    };

    use super::*;

    const ALICE: &str = "Basic YWxpY2U6c2VjcmV0"; // alice:secret

    enum FakeGateway {
        /// Behaves like ws2tcp-router: 401 without the right credentials, else the health check.
        Router,
        /// Accepts the handshake, then sends an unrelated message.
        WrongReply,
        /// Answers the health check message, but without a token header.
        WithoutToken,
        /// Drops the connection without answering, like a router without the health check.
        Hangup,
    }

    /// Serves one connection on a random local port and returns the gateway URL.
    #[allow(clippy::result_large_err)]
    async fn spawn_gateway(kind: FakeGateway) -> Gateway {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            match kind {
                FakeGateway::Hangup => drop(stream),
                FakeGateway::WithoutToken => {
                    let mut ws =
                        accept_hdr_async(stream, |_: &Request, response: Response| Ok(response))
                            .await
                            .unwrap();
                    futures_util::SinkExt::send(
                        &mut ws,
                        Message::Text("ok: ws2tcp-router 0.0.0 is available".into()),
                    )
                    .await
                    .unwrap();
                }
                FakeGateway::WrongReply => {
                    let mut ws =
                        accept_hdr_async(stream, |_: &Request, response: Response| Ok(response))
                            .await
                            .unwrap();
                    futures_util::SinkExt::send(&mut ws, Message::Text("hello".into()))
                        .await
                        .unwrap();
                }
                FakeGateway::Router => {
                    let result =
                        accept_hdr_async(stream, |request: &Request, response: Response| {
                            let authorized = request
                                .headers()
                                .get("authorization")
                                .is_some_and(|value| value == ALICE);
                            if authorized {
                                let mut response = response;
                                response
                                    .headers_mut()
                                    .insert(TOKEN_HEADER, HeaderValue::from_static("tok-123"));
                                Ok(response)
                            } else {
                                let mut error =
                                    ErrorResponse::new(Some("authentication required".into()));
                                *error.status_mut() = StatusCode::UNAUTHORIZED;
                                Err(error)
                            }
                        })
                        .await;
                    if let Ok(mut ws) = result {
                        futures_util::SinkExt::send(
                            &mut ws,
                            Message::Text(
                                "ok: ws2tcp-router 0.0.0 is available; health check only".into(),
                            ),
                        )
                        .await
                        .unwrap();
                    }
                }
            }
        });

        Gateway::parse(&format!("ws://{addr}")).unwrap()
    }

    #[tokio::test]
    async fn passes_with_correct_credentials() {
        let gateway = spawn_gateway(FakeGateway::Router).await;
        let health = check_gateway(&gateway, Some(ALICE), false, &[])
            .await
            .expect("health check should pass");

        let token = health.token.expect("router hands out a token");
        assert_eq!(token, "tok-123");
        assert!(token.is_sensitive());
    }

    #[tokio::test]
    async fn passes_without_a_token_from_the_gateway() {
        let gateway = spawn_gateway(FakeGateway::WithoutToken).await;
        let health = check_gateway(&gateway, None, false, &[])
            .await
            .expect("a gateway that sends no token is still usable");

        assert!(health.token.is_none());
    }

    #[test]
    fn tunnel_requests_carry_token_and_basic_auth() {
        let user_agent = (
            HeaderName::from_static("user-agent"),
            HeaderValue::from_static("ws2tcp-local/test"),
        );
        let stale_token = (
            HeaderName::from_static(TOKEN_HEADER),
            HeaderValue::from_static("stale"),
        );
        let headers = headers_with_token(
            vec![user_agent, stale_token],
            Some(HeaderValue::from_static("tok-123")),
        );

        let request =
            build_gateway_request("ws://gw.example/tcp:host:443", Some(ALICE), &headers).unwrap();
        assert_eq!(request.headers().get("authorization").unwrap(), ALICE);
        assert_eq!(request.headers().get(TOKEN_HEADER).unwrap(), "tok-123");
        assert_eq!(
            request.headers().get("user-agent").unwrap(),
            "ws2tcp-local/test"
        );
        assert_eq!(request.headers().get_all(TOKEN_HEADER).iter().count(), 1);
    }

    #[test]
    fn headers_are_unchanged_without_a_token() {
        let headers = vec![(
            HeaderName::from_static("user-agent"),
            HeaderValue::from_static("ws2tcp-local/test"),
        )];

        assert_eq!(headers_with_token(headers.clone(), None), headers);
    }

    #[tokio::test]
    async fn reports_wrong_credentials() {
        let gateway = spawn_gateway(FakeGateway::Router).await;
        let err = check_gateway(&gateway, Some("Basic YWxpY2U6d3Jvbmc="), false, &[])
            .await
            .unwrap_err();

        assert!(
            matches!(
                err,
                GatewayCheckError::Unauthorized {
                    credentials_configured: true
                }
            ),
            "{err}"
        );
        assert!(
            err.to_string()
                .contains("rejected the Basic Auth credentials")
        );
    }

    #[tokio::test]
    async fn reports_missing_credentials() {
        let gateway = spawn_gateway(FakeGateway::Router).await;
        let err = check_gateway(&gateway, None, false, &[]).await.unwrap_err();

        assert!(
            matches!(
                err,
                GatewayCheckError::Unauthorized {
                    credentials_configured: false
                }
            ),
            "{err}"
        );
        assert!(err.to_string().contains("no credentials were configured"));
    }

    #[tokio::test]
    async fn fails_on_unexpected_reply() {
        let gateway = spawn_gateway(FakeGateway::WrongReply).await;
        let err = check_gateway(&gateway, None, false, &[]).await.unwrap_err();

        assert!(matches!(err, GatewayCheckError::Failed(_)), "{err}");
    }

    #[tokio::test]
    async fn fails_when_gateway_hangs_up() {
        let gateway = spawn_gateway(FakeGateway::Hangup).await;
        let err = check_gateway(&gateway, None, false, &[]).await.unwrap_err();

        assert!(matches!(err, GatewayCheckError::Failed(_)), "{err}");
        assert!(
            err.to_string().contains("without the `/` health check"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn fails_when_gateway_is_unreachable() {
        // Bind then drop to get a port nothing listens on.
        let addr = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let gateway = Gateway::parse(&format!("ws://{addr}")).unwrap();

        let err = check_gateway(&gateway, None, false, &[]).await.unwrap_err();
        assert!(matches!(err, GatewayCheckError::Failed(_)), "{err}");
        assert!(!err.to_string().contains("health check does this"), "{err}");
    }
}
