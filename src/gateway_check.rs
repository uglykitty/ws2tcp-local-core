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

/// What a ws2tcp-router health check (`GET <gateway>/`) answers with as its first message.
const HEALTH_CHECK_MESSAGE_PREFIX: &str = "ok: ws2tcp-router";

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
    /// In token mode, the token login that stands in for the health check failed for another
    /// reason than rejected credentials: the gateway is unreachable, is not a ws2tcp-router, or
    /// does not offer token authentication.
    LoginFailed(String),
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
            Self::LoginFailed(reason) => write!(f, "gateway token login failed: {reason}"),
        }
    }
}

impl std::error::Error for GatewayCheckError {}

/// Verifies the gateway before serving: performs a websocket handshake on the gateway root, with
/// the same Basic Auth credentials, custom headers and TLS settings as real tunnels, and expects
/// the ws2tcp-router health check message. (The health check accepts Basic Auth even when the
/// router requires tokens for tunnels.)
pub(crate) async fn check_gateway(
    gateway: &Gateway,
    basic_auth: Option<&str>,
    insecure: bool,
    headers: &[(HeaderName, HeaderValue)],
) -> Result<(), GatewayCheckError> {
    let url = gateway.health_check_url();
    let request = build_gateway_request(&url, basic_auth, headers)
        .map_err(|err| GatewayCheckError::Failed(format!("{err:#}")))?;

    let check = async {
        let (mut websocket, _) =
            connect_async_tls_with_config(request, None, false, gateway_connector(insecure))
                .await
                .map_err(|err| classify_connect_error(err, basic_auth.is_some()))?;

        match websocket.next().await {
            Some(Ok(Message::Text(text))) if text.starts_with(HEALTH_CHECK_MESSAGE_PREFIX) => {
                Ok(())
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

        check_gateway(&gateway, Some(ALICE), false, &[])
            .await
            .expect("health check should pass");
    }

    #[test]
    fn gateway_request_carries_the_authorization_and_custom_headers() {
        let headers = vec![(
            HeaderName::from_static("user-agent"),
            HeaderValue::from_static("ws2tcp-local/test"),
        )];

        let request =
            build_gateway_request("ws://gw.example/tcp:host:443", Some(ALICE), &headers).unwrap();
        assert_eq!(request.headers().get("authorization").unwrap(), ALICE);
        assert!(
            request
                .headers()
                .get("authorization")
                .unwrap()
                .is_sensitive()
        );
        assert_eq!(
            request.headers().get("user-agent").unwrap(),
            "ws2tcp-local/test"
        );

        let request = build_gateway_request("ws://gw.example/tcp:host:443", None, &[]).unwrap();
        assert!(request.headers().get("authorization").is_none());
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
