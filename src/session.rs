//! How the client authenticates tunnel requests to the gateway.
//!
//! Exactly one method is used at a time, chosen by [`AuthMode`](crate::AuthMode):
//!
//! - **Basic**: the health check, then Basic Auth on every connection ([`GatewayAuth::Basic`]).
//! - **Token**: the client logs in once with the Basic Auth credentials (`POST /auth/token`) and
//!   opens tunnels with a short-lived access token (`Authorization: Bearer ...`), so the password
//!   no longer travels with every connection. There is no health check: the login is the check.
//!   A background task renews the access token with the refresh token (`POST /auth/refresh`)
//!   once 80% of its lifetime is used, on its own: neither the application nor the tunnels take
//!   part. When the refresh token is rejected too (it expired, or the router restarted), the
//!   client logs in again. Tunnels still check the token when they open, which covers a failed
//!   renewal and a token that the router refused. It never falls back to Basic Auth on tunnels.

use std::{
    fmt,
    sync::{Arc, Weak},
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow};
use reqwest::{
    Client,
    header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue},
    redirect::Policy,
};
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::{gateway::Gateway, gateway_check::GatewayCheckError, upstream::UpstreamProxy};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Refuse to buffer a token response larger than this.
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;
/// How long to wait before trying again to renew tokens, after a renewal failed for a reason
/// that is not the router rejecting them (typically the network) while the access token still
/// works.
const RENEW_RETRY_DELAY: Duration = Duration::from_secs(5);
/// The background renewal never runs more often than this, whatever lifetime the gateway names, so
/// that a pathological one cannot turn it into a request loop.
const MIN_BACKGROUND_INTERVAL: Duration = Duration::from_secs(1);
/// The longest the background renewal waits before trying again after failures. It starts at
/// [`RENEW_RETRY_DELAY`] and doubles with every failure in a row.
const MAX_BACKGROUND_RETRY_DELAY: Duration = Duration::from_secs(300);

/// The credentials sent to the gateway on a tunnel request.
#[derive(Clone)]
pub(crate) enum GatewayAuth {
    /// No credentials are configured.
    None,
    /// Basic Auth on every request.
    Basic(String),
    /// A token login, renewed as needed.
    Token(Arc<TokenSession>),
}

impl fmt::Debug for GatewayAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print credentials.
        f.write_str(self.describe())
    }
}

impl GatewayAuth {
    /// Logs in for tokens, which is all the checking there is in token mode: no health check is
    /// sent. Rejected credentials fail with [`GatewayCheckError::Unauthorized`], and any other
    /// failure to log in (the gateway is unreachable, is not a ws2tcp-router, or has no token
    /// authentication) with [`GatewayCheckError::LoginFailed`]. There is no fallback to Basic
    /// Auth.
    pub(crate) async fn login(
        gateway: &Gateway,
        basic_auth: String,
        insecure: bool,
        upstream_proxy: Option<&UpstreamProxy>,
        headers: &[(HeaderName, HeaderValue)],
    ) -> Result<Self, GatewayCheckError> {
        let session = TokenSession::new(gateway, &basic_auth, insecure, upstream_proxy, headers)
            .map_err(|err| GatewayCheckError::LoginFailed(format!("{err:#}")))?;
        let login = {
            let mut state = session.state.lock().await;
            session.renew(&mut state).await
        };
        match login {
            Ok(()) => {
                let session = Arc::new(session);
                // Only a weak reference, so that the task ends when the session is dropped.
                tokio::spawn(keep_fresh(Arc::downgrade(&session)));
                Ok(Self::Token(session))
            }
            Err(RequestError::Rejected) => Err(GatewayCheckError::Unauthorized {
                credentials_configured: true,
            }),
            Err(RequestError::Failed(reason)) => Err(GatewayCheckError::LoginFailed(format!(
                "{reason:#} (POST {}); the gateway has to offer token authentication \
                 (a ws2tcp-router with Basic credentials configured)",
                gateway.auth_url("token")
            ))),
        }
    }

    /// A short description for logs.
    pub(crate) fn describe(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Basic(_) => "basic",
            Self::Token(_) => "token",
        }
    }

    /// The `Authorization` header value for the next tunnel request, renewing the access token
    /// first when it is about to run out.
    pub(crate) async fn authorization(&self) -> Result<Option<String>> {
        match self {
            Self::None => Ok(None),
            Self::Basic(basic_auth) => Ok(Some(basic_auth.clone())),
            Self::Token(session) => session.authorization().await.map(Some),
        }
    }

    /// Whether a rejected request can be retried after [`rejected`](Self::rejected).
    pub(crate) fn can_renew(&self) -> bool {
        matches!(self, Self::Token(_))
    }

    /// Tells that the gateway answered `401` to a request that carried `authorization` (a value
    /// returned by [`authorization`](Self::authorization)), so it is renewed on the next call
    /// instead of being reused. The router does this after a restart, or when the login was
    /// revoked.
    pub(crate) async fn rejected(&self, authorization: Option<&str>) {
        if let (Self::Token(session), Some(authorization)) = (self, authorization) {
            session.rejected(authorization).await;
        }
    }
}

struct Tokens {
    access: String,
    refresh: String,
    /// When the access token is renewed: some time before it runs out.
    renew_at: Instant,
    access_expires: Instant,
    refresh_expires: Instant,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    refresh_token: String,
    refresh_expires_in: u64,
}

impl TokenResponse {
    fn into_tokens(self, now: Instant) -> Result<Tokens> {
        for token in [&self.access_token, &self.refresh_token] {
            if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_graphic()) {
                return Err(anyhow!("gateway sent a malformed token"));
            }
        }

        let access_ttl = Duration::from_secs(self.expires_in);
        Ok(Tokens {
            access: self.access_token,
            refresh: self.refresh_token,
            // Renew once 80% of the lifetime is used up, so a request never starts with a token
            // that is about to expire.
            renew_at: now + access_ttl * 4 / 5,
            access_expires: now + access_ttl,
            refresh_expires: now + Duration::from_secs(self.refresh_expires_in),
        })
    }
}

/// Why a token request failed.
enum RequestError {
    /// The gateway answered `401`: the credential was refused.
    Rejected,
    /// Anything else: the gateway is not reachable, has no token endpoints, or answered oddly.
    Failed(anyhow::Error),
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected => f.write_str("the gateway rejected the credentials (401)"),
            Self::Failed(err) => write!(f, "{err:#}"),
        }
    }
}

impl From<RequestError> for anyhow::Error {
    fn from(err: RequestError) -> Self {
        anyhow!("gateway token request failed: {err}")
    }
}

pub(crate) struct TokenSession {
    client: Client,
    login_url: String,
    refresh_url: String,
    basic_auth: HeaderValue,
    headers: HeaderMap,
    /// `None` until the first login. Held across a renewal, so concurrent tunnels wait for one
    /// renewal instead of each starting their own (a refresh token can be used only once).
    state: Mutex<Option<Tokens>>,
}

impl TokenSession {
    fn new(
        gateway: &Gateway,
        basic_auth: &str,
        insecure: bool,
        upstream_proxy: Option<&UpstreamProxy>,
        headers: &[(HeaderName, HeaderValue)],
    ) -> Result<Self> {
        let mut basic_auth = HeaderValue::from_str(basic_auth)
            .map_err(|_| anyhow!("Basic authorization header contains invalid characters"))?;
        basic_auth.set_sensitive(true);

        let mut header_map = HeaderMap::new();
        for (name, value) in headers {
            header_map.insert(name.clone(), value.clone());
        }

        let mut client = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .danger_accept_invalid_certs(insecure)
            // Tunnels connect to the gateway the way the settings say, and ignore the proxy
            // environment variables, so the token requests do too.
            .no_proxy()
            // A redirect would send the credentials elsewhere.
            .redirect(Policy::none());
        if let Some(upstream_proxy) = upstream_proxy {
            client = client.proxy(
                upstream_proxy
                    .to_reqwest()
                    .map_err(|err| anyhow!("invalid upstream proxy: {}", err.without_url()))?,
            );
        }
        let client = client
            .build()
            .map_err(|err| anyhow!("failed to build the token client: {err}"))?;

        Ok(Self {
            client,
            login_url: gateway.auth_url("token"),
            refresh_url: gateway.auth_url("refresh"),
            basic_auth,
            headers: header_map,
            state: Mutex::new(None),
        })
    }

    async fn authorization(&self) -> Result<String> {
        let mut state = self.state.lock().await;

        let due = state
            .as_ref()
            .is_none_or(|tokens| Instant::now() >= tokens.renew_at);
        if due && let Err(err) = self.renew(&mut state).await {
            // A failed renewal is fatal only when there is no access token left to use.
            match state.as_mut() {
                Some(tokens) if Instant::now() < tokens.access_expires => {
                    warn!(error = %err, "failed to renew the gateway token; using the current one");
                    tokens.renew_at = Instant::now() + RENEW_RETRY_DELAY;
                }
                _ => return Err(err.into()),
            }
        }

        let tokens = state.as_ref().expect("a login or renewal filled the state");
        Ok(format!("Bearer {}", tokens.access))
    }

    /// How long until the background task should renew: until the access token is due, and not
    /// before `retry_at`, which is set after a failed renewal.
    async fn until_background_renewal(&self, retry_at: Option<Instant>) -> Duration {
        let now = Instant::now();
        let state = self.state.lock().await;
        let renew_at = state.as_ref().map_or(now, |tokens| tokens.renew_at);
        let due = retry_at.map_or(renew_at, |retry_at| renew_at.max(retry_at));
        due.saturating_duration_since(now)
            .max(MIN_BACKGROUND_INTERVAL)
    }

    /// Renews the tokens if they are due. Returns whether the renewal failed.
    async fn renew_in_background(&self) -> bool {
        let mut state = self.state.lock().await;
        // A tunnel may have renewed them while the task was asleep.
        if state
            .as_ref()
            .is_some_and(|tokens| Instant::now() < tokens.renew_at)
        {
            return false;
        }
        match self.renew(&mut state).await {
            Ok(()) => false,
            Err(err) => {
                warn!(error = %err, "failed to renew the gateway token in the background; will try again");
                true
            }
        }
    }

    async fn rejected(&self, authorization: &str) {
        let mut state = self.state.lock().await;
        if let Some(tokens) = state.as_mut()
            && authorization.strip_prefix("Bearer ") == Some(tokens.access.as_str())
        {
            tokens.renew_at = Instant::now();
        }
    }

    /// Replaces the tokens: with the refresh token when there is a usable one, else by logging in.
    async fn renew(&self, state: &mut Option<Tokens>) -> Result<(), RequestError> {
        if let Some(tokens) = state.as_ref()
            && Instant::now() < tokens.refresh_expires
        {
            let refresh = bearer(&tokens.refresh);
            match self.request(&self.refresh_url, refresh).await {
                Ok(fresh) => {
                    debug!("refreshed the gateway access token");
                    *state = Some(fresh);
                    return Ok(());
                }
                Err(RequestError::Rejected) => {
                    info!("gateway refused the refresh token; logging in again");
                }
                // Not a verdict on the refresh token; logging in would likely fail as well.
                Err(err @ RequestError::Failed(_)) => return Err(err),
            }
        }

        let fresh = self
            .request(&self.login_url, self.basic_auth.clone())
            .await?;
        debug!("logged in to the gateway");
        *state = Some(fresh);
        Ok(())
    }

    async fn request(
        &self,
        url: &str,
        mut authorization: HeaderValue,
    ) -> Result<Tokens, RequestError> {
        authorization.set_sensitive(true);
        let response = self
            .client
            .post(url)
            .headers(self.headers.clone())
            .header(AUTHORIZATION, authorization)
            .send()
            .await
            .map_err(|err| RequestError::Failed(anyhow!("{}", err.without_url())))?;

        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(RequestError::Rejected);
        }
        if !status.is_success() {
            return Err(RequestError::Failed(anyhow!(
                "gateway answered HTTP {status}"
            )));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES)
        {
            return Err(RequestError::Failed(anyhow!("token response is too large")));
        }

        let body = response
            .bytes()
            .await
            .map_err(|err| RequestError::Failed(anyhow!("{}", err.without_url())))?;
        let parsed: TokenResponse = serde_json::from_slice(&body)
            .map_err(|err| RequestError::Failed(anyhow!("malformed token response: {err}")))?;
        parsed
            .into_tokens(Instant::now())
            .map_err(RequestError::Failed)
    }
}

/// Renews the tokens of `session` when they are due, for as long as the session lives, so that
/// tunnels find a fresh access token waiting for them.
async fn keep_fresh(session: Weak<TokenSession>) {
    let mut failures = 0_u32;
    let mut retry_at = None;
    loop {
        let Some(current) = session.upgrade() else {
            return;
        };
        let wait = current.until_background_renewal(retry_at).await;
        // Do not keep the session alive while asleep.
        drop(current);
        tokio::time::sleep(wait).await;

        let Some(current) = session.upgrade() else {
            return;
        };
        if current.renew_in_background().await {
            let delay = RENEW_RETRY_DELAY
                .saturating_mul(2_u32.saturating_pow(failures))
                .min(MAX_BACKGROUND_RETRY_DELAY);
            failures = failures.saturating_add(1);
            retry_at = Some(Instant::now() + delay);
        } else {
            failures = 0;
            retry_at = None;
        }
    }
}

fn bearer(token: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("Bearer {token}"))
        .expect("tokens were checked to be printable ASCII")
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;

    const ALICE: &str = "Basic YWxpY2U6c2VjcmV0"; // alice:secret

    /// What the fake gateway saw: the request path and its `Authorization` header.
    type Seen = Arc<StdMutex<Vec<(String, Option<String>)>>>;

    /// Serves one HTTP/1.1 response per connection, as chosen by `handler` from the request path
    /// and `Authorization` header. An empty response closes the connection without answering.
    async fn spawn_gateway(
        handler: impl Fn(&str, Option<&str>) -> String + Send + Sync + 'static,
    ) -> (Gateway, Seen) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Seen = Arc::default();
        let recorded = Arc::clone(&seen);
        let handler = Arc::new(handler);

        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let (handler, recorded) = (Arc::clone(&handler), Arc::clone(&recorded));
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut chunk = [0_u8; 1024];
                    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                        let n = stream.read(&mut chunk).await.unwrap();
                        if n == 0 {
                            return;
                        }
                        head.extend_from_slice(&chunk[..n]);
                    }
                    let head = String::from_utf8_lossy(&head).into_owned();
                    let mut lines = head.lines();
                    let path = lines
                        .next()
                        .and_then(|line| line.split(' ').nth(1))
                        .unwrap_or_default()
                        .to_owned();
                    let authorization = lines.find_map(|line| {
                        let (name, value) = line.split_once(": ")?;
                        name.eq_ignore_ascii_case("authorization")
                            .then(|| value.to_owned())
                    });

                    let response = handler(&path, authorization.as_deref());
                    recorded.lock().unwrap().push((path, authorization));
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        (Gateway::parse(&format!("ws://{addr}")).unwrap(), seen)
    }

    fn tokens_response(access: &str, refresh: &str, expires_in: u64) -> String {
        let body = format!(
            r#"{{"token_type":"Bearer","access_token":"{access}","expires_in":{expires_in},"refresh_token":"{refresh}","refresh_expires_in":3600}}"#
        );
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    fn status_response(status: &str) -> String {
        format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
    }

    /// A gateway that logs `alice:secret` in as `access-N`/`refresh-N`, and refreshes with the
    /// latest refresh token only.
    fn router_like(expires_in: u64) -> impl Fn(&str, Option<&str>) -> String + Send + Sync {
        let issued = StdMutex::new(0_u32);
        move |path, authorization| {
            let mut issued = issued.lock().unwrap();
            match (path, authorization) {
                ("/auth/token", Some(ALICE)) => {
                    *issued += 1;
                    tokens_response(
                        &format!("access-{issued}"),
                        &format!("refresh-{issued}"),
                        expires_in,
                    )
                }
                ("/auth/refresh", Some(value)) if value == format!("Bearer refresh-{issued}") => {
                    *issued += 1;
                    tokens_response(
                        &format!("access-{issued}"),
                        &format!("refresh-{issued}"),
                        expires_in,
                    )
                }
                _ => status_response("401 Unauthorized"),
            }
        }
    }

    async fn login(gateway: &Gateway, basic_auth: &str) -> GatewayAuth {
        GatewayAuth::login(gateway, basic_auth.to_owned(), false, None, &[])
            .await
            .expect("the login should work")
    }

    fn paths(seen: &Seen) -> Vec<String> {
        seen.lock()
            .unwrap()
            .iter()
            .map(|(path, _)| path.clone())
            .collect()
    }

    #[tokio::test]
    async fn logs_in_once_and_reuses_the_access_token() {
        let (gateway, seen) = spawn_gateway(router_like(600)).await;
        let auth = login(&gateway, ALICE).await;

        assert_eq!(auth.describe(), "token");
        for _ in 0..3 {
            assert_eq!(
                auth.authorization().await.unwrap().as_deref(),
                Some("Bearer access-1")
            );
        }
        assert_eq!(paths(&seen), ["/auth/token"]);
        assert_eq!(
            seen.lock().unwrap()[0].1.as_deref(),
            Some(ALICE),
            "the login carries the Basic Auth credentials"
        );
    }

    #[tokio::test]
    async fn renews_with_the_refresh_token_before_the_access_token_runs_out() {
        // An access token that lives 0 seconds is due for renewal at once.
        let (gateway, seen) = spawn_gateway(router_like(0)).await;
        let auth = login(&gateway, ALICE).await;

        assert_eq!(
            auth.authorization().await.unwrap().as_deref(),
            Some("Bearer access-2")
        );
        assert_eq!(
            auth.authorization().await.unwrap().as_deref(),
            Some("Bearer access-3")
        );
        assert_eq!(
            paths(&seen),
            ["/auth/token", "/auth/refresh", "/auth/refresh"]
        );
        // The refresh token, not the password, is what renews.
        assert_eq!(
            seen.lock().unwrap()[1].1.as_deref(),
            Some("Bearer refresh-1")
        );
    }

    #[tokio::test]
    async fn logs_in_again_when_the_refresh_token_is_rejected() {
        let logins = Arc::new(StdMutex::new(0_u32));
        let counted = Arc::clone(&logins);
        // Refreshing never works, as after a router restart.
        let (gateway, seen) =
            spawn_gateway(move |path, authorization| match (path, authorization) {
                ("/auth/token", Some(ALICE)) => {
                    let mut logins = counted.lock().unwrap();
                    *logins += 1;
                    tokens_response(&format!("access-{logins}"), "refresh", 0)
                }
                _ => status_response("401 Unauthorized"),
            })
            .await;
        let auth = login(&gateway, ALICE).await;

        assert_eq!(
            auth.authorization().await.unwrap().as_deref(),
            Some("Bearer access-2")
        );
        assert_eq!(*logins.lock().unwrap(), 2);
        assert_eq!(
            paths(&seen),
            ["/auth/token", "/auth/refresh", "/auth/token"]
        );
    }

    #[tokio::test]
    async fn a_rejected_access_token_is_replaced_on_the_next_call() {
        let (gateway, seen) = spawn_gateway(router_like(600)).await;
        let auth = login(&gateway, ALICE).await;

        let used = auth.authorization().await.unwrap();
        assert!(auth.can_renew());
        auth.rejected(used.as_deref()).await;

        assert_eq!(
            auth.authorization().await.unwrap().as_deref(),
            Some("Bearer access-2")
        );
        assert_eq!(paths(&seen), ["/auth/token", "/auth/refresh"]);

        // Reporting a token that is no longer current changes nothing.
        auth.rejected(used.as_deref()).await;
        assert_eq!(
            auth.authorization().await.unwrap().as_deref(),
            Some("Bearer access-2")
        );
        assert_eq!(paths(&seen).len(), 2);
    }

    #[tokio::test]
    async fn token_requests_go_through_the_upstream_proxy() {
        // The fake "proxy" is the only thing listening; the gateway name does not resolve, so a
        // login that succeeds cannot have been made directly.
        let router = router_like(3600);
        let (proxy, seen) = spawn_gateway(move |path, authorization| {
            router(
                path.strip_prefix("http://gateway.invalid:8000")
                    .unwrap_or(path),
                authorization,
            )
        })
        .await;
        let upstream_proxy =
            UpstreamProxy::parse(&proxy.base().replace("ws://", "http://")).unwrap();
        let gateway = Gateway::parse("ws://gateway.invalid:8000").unwrap();

        let auth = GatewayAuth::login(
            &gateway,
            ALICE.to_owned(),
            false,
            Some(&upstream_proxy),
            &[],
        )
        .await
        .expect("the login should work through the proxy");

        assert_eq!(
            auth.authorization().await.unwrap().as_deref(),
            Some("Bearer access-1")
        );
        assert_eq!(paths(&seen), ["http://gateway.invalid:8000/auth/token"]);
    }

    #[tokio::test]
    async fn concurrent_requests_share_one_renewal() {
        let (gateway, seen) = spawn_gateway(router_like(0)).await;
        let auth = login(&gateway, ALICE).await;

        let auth = Arc::new(auth);
        let calls: Vec<_> = (0..5)
            .map(|_| {
                let auth = Arc::clone(&auth);
                tokio::spawn(async move { auth.authorization().await.unwrap() })
            })
            .collect();
        for call in calls {
            call.await.unwrap();
        }

        // Every call finds the token due (it lives 0 seconds), but a refresh token can be used
        // only once: each renewal used the token the previous one handed out, in turn.
        let paths = paths(&seen);
        assert_eq!(paths[0], "/auth/token");
        assert!(paths[1..].iter().all(|path| path == "/auth/refresh"));
        let seen = seen.lock().unwrap();
        for (index, (_, authorization)) in seen[1..].iter().enumerate() {
            assert_eq!(
                authorization.as_deref(),
                Some(format!("Bearer refresh-{}", index + 1).as_str())
            );
        }
    }

    #[tokio::test]
    async fn wrong_credentials_fail_the_login_as_unauthorized() {
        let (gateway, _) = spawn_gateway(router_like(600)).await;
        let err = GatewayAuth::login(
            &gateway,
            "Basic YWxpY2U6d3Jvbmc=".to_owned(),
            false,
            None,
            &[],
        )
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
    }

    #[tokio::test]
    async fn custom_headers_are_sent_on_token_requests() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen_head = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0_u8; 2048];
            let n = stream.read(&mut buffer).await.unwrap();
            let _ = stream
                .write_all(status_response("404 Not Found").as_bytes())
                .await;
            String::from_utf8_lossy(&buffer[..n]).to_lowercase()
        });

        let gateway = Gateway::parse(&format!("ws://{addr}")).unwrap();
        let headers = [(
            HeaderName::from_static("user-agent"),
            HeaderValue::from_static("ws2tcp-local/test"),
        )];
        // The login fails (404), which is all this test needs of the response.
        let _ = GatewayAuth::login(&gateway, ALICE.to_owned(), false, None, &headers).await;

        let head = seen_head.await.unwrap();
        assert!(head.starts_with("post /auth/token http/1.1"), "{head}");
        assert!(head.contains("user-agent: ws2tcp-local/test"), "{head}");
    }

    #[tokio::test]
    async fn a_login_that_cannot_be_completed_is_an_error_and_never_a_fallback() {
        for response in [
            status_response("404 Not Found"),
            status_response("403 Forbidden"),
            // An older router closes the connection on a path it does not know.
            String::new(),
            // Not tokens.
            {
                let body = r#"{"access_token":"a b","expires_in":1,"refresh_token":"r","refresh_expires_in":1}"#;
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
            },
        ] {
            let (gateway, seen) = spawn_gateway(move |_, _| response.clone()).await;
            let err = GatewayAuth::login(&gateway, ALICE.to_owned(), false, None, &[])
                .await
                .unwrap_err();

            assert!(matches!(err, GatewayCheckError::LoginFailed(_)), "{err}");
            let message = err.to_string();
            assert!(
                message.starts_with("gateway token login failed: "),
                "{message}"
            );
            assert!(message.contains("/auth/token"), "{message}");
            assert!(
                message.contains("has to offer token authentication"),
                "{message}"
            );
            // The token endpoint was the only thing asked: no health check, no Basic Auth tunnel.
            assert_eq!(paths(&seen), ["/auth/token"]);
        }
    }

    #[tokio::test]
    async fn an_unreachable_gateway_fails_the_login() {
        // Bind then drop to get a port nothing listens on.
        let addr = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let gateway = Gateway::parse(&format!("ws://{addr}")).unwrap();

        let err = GatewayAuth::login(&gateway, ALICE.to_owned(), false, None, &[])
            .await
            .unwrap_err();
        assert!(matches!(err, GatewayCheckError::LoginFailed(_)), "{err}");
    }

    #[tokio::test]
    async fn basic_mode_and_anonymous_send_only_what_is_configured() {
        let basic = GatewayAuth::Basic(ALICE.to_owned());
        assert_eq!(basic.describe(), "basic");
        assert_eq!(basic.authorization().await.unwrap().as_deref(), Some(ALICE));
        assert!(!basic.can_renew());

        let anonymous = GatewayAuth::None;
        assert_eq!(anonymous.describe(), "none");
        assert_eq!(anonymous.authorization().await.unwrap(), None);
    }

    #[tokio::test]
    async fn the_access_token_is_renewed_in_the_background_without_any_tunnel() {
        // An access token that lives 2 seconds is due after 1.6 s. Nothing asks for it here.
        let (gateway, seen) = spawn_gateway(router_like(2)).await;
        let auth = login(&gateway, ALICE).await;
        assert_eq!(paths(&seen), ["/auth/token"]);

        tokio::time::sleep(Duration::from_millis(2500)).await;

        // The renewal has happened on its own, with the refresh token and not the password...
        assert_eq!(paths(&seen), ["/auth/token", "/auth/refresh"]);
        assert_eq!(
            seen.lock().unwrap()[1].1.as_deref(),
            Some("Bearer refresh-1")
        );
        // ...so the first tunnel finds a fresh token and does not have to renew.
        assert_eq!(
            auth.authorization().await.unwrap().as_deref(),
            Some("Bearer access-2")
        );
        assert_eq!(paths(&seen), ["/auth/token", "/auth/refresh"]);
    }

    #[tokio::test]
    async fn the_background_renewal_ends_with_the_session() {
        let (gateway, seen) = spawn_gateway(router_like(2)).await;
        let auth = login(&gateway, ALICE).await;
        drop(auth);

        tokio::time::sleep(Duration::from_millis(2500)).await;

        // Nobody holds the session any more: it is not renewed.
        assert_eq!(paths(&seen), ["/auth/token"]);
    }

    #[test]
    fn debug_output_never_contains_credentials() {
        let basic = GatewayAuth::Basic(ALICE.to_owned());

        assert_eq!(format!("{basic:?}"), "basic");
    }
}
