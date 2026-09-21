//! An upstream proxy server that all outgoing connections are made through.
//!
//! It is given as a URL: `http://[user:pass@]host[:port]` (an HTTP proxy, used with `CONNECT`),
//! `socks5h://[user:pass@]host[:port]` (a SOCKS5 proxy that resolves hostnames itself) or
//! `socks5://[user:pass@]host[:port]` (a SOCKS5 proxy for which hostnames are resolved locally).
//! With one configured, nothing leaves the machine around it: the tunnels, the health check and the
//! token requests to the gateway, the requests that a routing rule sends direct, and the downloads
//! of the rule lists.

use std::{fmt, io, time::Duration};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use percent_encoding::percent_decode_str;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, lookup_host},
    time::timeout,
};
use tokio_socks::tcp::Socks5Stream;
use url::Url;

/// How long the connection to the proxy and its handshake may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// The longest response header of an HTTP proxy that is accepted.
const MAX_CONNECT_RESPONSE_BYTES: usize = 8 * 1024;
const DEFAULT_HTTP_PORT: u16 = 80;
const DEFAULT_SOCKS_PORT: u16 = 1080;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Http,
    /// SOCKS5 with the hostname resolved locally (`socks5://`).
    Socks5,
    /// SOCKS5 with the hostname resolved by the proxy (`socks5h://`).
    Socks5h,
}

impl Kind {
    fn scheme(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Socks5 => "socks5",
            Self::Socks5h => "socks5h",
        }
    }
}

#[derive(Clone)]
pub struct UpstreamProxy {
    kind: Kind,
    host: String,
    port: u16,
    credentials: Option<(String, String)>,
    /// The URL as given, with the credentials still percent-encoded, for the HTTP client.
    url: Url,
}

impl UpstreamProxy {
    /// Parses `http://`, `socks5://` or `socks5h://` URLs.
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        // The error of `Url::parse` never quotes the input, so it cannot leak the credentials.
        let url = Url::parse(input)
            .map_err(|err| anyhow::anyhow!("invalid upstream proxy URL: {err}"))?;
        let kind = match url.scheme() {
            "http" => Kind::Http,
            "socks5" => Kind::Socks5,
            "socks5h" => Kind::Socks5h,
            scheme => {
                bail!("upstream proxy URL scheme must be http, socks5 or socks5h, got {scheme}")
            }
        };
        if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
            bail!("upstream proxy URL must not contain a path, query or fragment");
        }
        let Some(host) = url.host_str().filter(|host| !host.is_empty()) else {
            bail!("upstream proxy URL has no host");
        };
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host)
            .to_owned();
        let port = url.port().unwrap_or(match kind {
            Kind::Http => DEFAULT_HTTP_PORT,
            Kind::Socks5 | Kind::Socks5h => DEFAULT_SOCKS_PORT,
        });

        let credentials = if url.username().is_empty() && url.password().is_none() {
            None
        } else {
            let decode = |value: &str| {
                percent_decode_str(value)
                    .decode_utf8()
                    .map(|value| value.into_owned())
                    .context("upstream proxy credentials must be valid UTF-8")
            };
            Some((
                decode(url.username())?,
                decode(url.password().unwrap_or_default())?,
            ))
        };

        Ok(Self {
            kind,
            host,
            port,
            credentials,
            url,
        })
    }

    /// Like [`parse`](Self::parse), for an optional setting where a missing or blank value means
    /// that no upstream proxy is used.
    pub fn parse_optional(input: Option<&str>) -> Result<Option<Self>> {
        match input.map(str::trim) {
            None | Some("") => Ok(None),
            Some(input) => Self::parse(input).map(Some),
        }
    }

    /// The proxy for the HTTP client of the token requests.
    pub(crate) fn to_reqwest(&self) -> reqwest::Result<reqwest::Proxy> {
        reqwest::Proxy::all(self.url.as_str())
    }

    /// Opens a TCP connection to `host:port` through the proxy.
    ///
    /// Failures are returned as [`io::ErrorKind::Other`] errors that name the proxy (without its
    /// credentials), so they cannot be mistaken for a problem with the target.
    pub(crate) async fn connect(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        match timeout(CONNECT_TIMEOUT, self.connect_inner(host, port)).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(err)) => Err(io::Error::other(format!(
                "upstream proxy {self} failed to connect {host}:{port}: {err:#}"
            ))),
            Err(_) => Err(io::Error::other(format!(
                "upstream proxy {self} did not connect {host}:{port} within {} seconds",
                CONNECT_TIMEOUT.as_secs()
            ))),
        }
    }

    async fn connect_inner(&self, host: &str, port: u16) -> Result<TcpStream> {
        let mut stream = TcpStream::connect((self.host.as_str(), self.port))
            .await
            .context("cannot reach the proxy")?;
        let _ = stream.set_nodelay(true);

        match self.kind {
            Kind::Http => {
                self.http_connect(&mut stream, host, port).await?;
                Ok(stream)
            }
            Kind::Socks5h => self.socks5(stream, (host, port)).await,
            Kind::Socks5 => {
                let address = lookup_host((host, port))
                    .await
                    .with_context(|| format!("cannot resolve {host} locally"))?
                    .next()
                    .with_context(|| format!("{host} has no address"))?;
                self.socks5(stream, address).await
            }
        }
    }

    async fn socks5<'a>(
        &self,
        stream: TcpStream,
        target: impl tokio_socks::IntoTargetAddr<'a>,
    ) -> Result<TcpStream> {
        let stream = match &self.credentials {
            Some((username, password)) => {
                Socks5Stream::connect_with_password_and_socket(stream, target, username, password)
                    .await
            }
            None => Socks5Stream::connect_with_socket(stream, target).await,
        }
        .map_err(|err| anyhow::anyhow!("{err}"))?;
        Ok(stream.into_inner())
    }

    async fn http_connect(&self, stream: &mut TcpStream, host: &str, port: u16) -> Result<()> {
        let authority = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
        if let Some((username, password)) = &self.credentials {
            let credentials = STANDARD.encode(format!("{username}:{password}"));
            request.push_str(&format!("Proxy-Authorization: Basic {credentials}\r\n"));
        }
        request.push_str("\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .context("cannot send the CONNECT request")?;

        // Read the response header and not a byte more: what follows belongs to the tunnel.
        let mut response = Vec::new();
        let mut byte = [0_u8; 1];
        while !response.ends_with(b"\r\n\r\n") {
            if response.len() >= MAX_CONNECT_RESPONSE_BYTES {
                bail!("the CONNECT response is too large");
            }
            if stream
                .read(&mut byte)
                .await
                .context("cannot read the CONNECT response")?
                == 0
            {
                bail!("the proxy closed the connection without answering CONNECT");
            }
            response.push(byte[0]);
        }

        let status_line = String::from_utf8_lossy(&response)
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned();
        let mut parts = status_line.split_whitespace();
        let version = parts.next().unwrap_or_default();
        let status = parts.next().unwrap_or_default();
        if !version.starts_with("HTTP/") {
            bail!("the proxy did not answer like an HTTP proxy");
        }
        match status {
            status if status.starts_with('2') => Ok(()),
            "407" => bail!(
                "the proxy requires authentication (407 Proxy Authentication Required); \
                 check the credentials in the upstream proxy URL"
            ),
            _ => bail!("the proxy answered CONNECT with: {status_line}"),
        }
    }
}

/// Shows the scheme, host and port only, so that logs and errors never carry the credentials.
impl fmt::Display for UpstreamProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "{}://[{}]:{}", self.kind.scheme(), self.host, self.port)
        } else {
            write!(f, "{}://{}:{}", self.kind.scheme(), self.host, self.port)
        }
    }
}

impl fmt::Debug for UpstreamProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UpstreamProxy({self}")?;
        if self.credentials.is_some() {
            f.write_str(", credentials: <hidden>")?;
        }
        f.write_str(")")
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn parses_the_supported_schemes() {
        let proxy = UpstreamProxy::parse("http://proxy.example:8080").unwrap();
        assert_eq!(proxy.to_string(), "http://proxy.example:8080");
        let proxy = UpstreamProxy::parse("socks5h://127.0.0.1:1081/").unwrap();
        assert_eq!(proxy.to_string(), "socks5h://127.0.0.1:1081");
        let proxy = UpstreamProxy::parse("socks5://[::1]:9050").unwrap();
        assert_eq!(proxy.to_string(), "socks5://[::1]:9050");
        assert_eq!(proxy.host, "::1");
    }

    #[test]
    fn applies_the_default_ports() {
        assert_eq!(UpstreamProxy::parse("http://p.example").unwrap().port, 80);
        assert_eq!(
            UpstreamProxy::parse("socks5h://p.example").unwrap().port,
            1080
        );
    }

    #[test]
    fn rejects_unsupported_or_malformed_urls() {
        for input in [
            "ftp://p.example:21",
            "https://p.example:443",
            "socks4://p.example:1080",
            "p.example:8080",
            "http://",
            "http://p.example:8080/path",
            "http://p.example:8080/?x=1",
            "http://p.example:99999",
        ] {
            assert!(UpstreamProxy::parse(input).is_err(), "{input}");
        }
    }

    #[test]
    fn blank_means_no_proxy() {
        assert!(UpstreamProxy::parse_optional(None).unwrap().is_none());
        assert!(UpstreamProxy::parse_optional(Some("  ")).unwrap().is_none());
        assert!(
            UpstreamProxy::parse_optional(Some("http://p.example:1"))
                .unwrap()
                .is_some()
        );
        assert!(UpstreamProxy::parse_optional(Some("nonsense")).is_err());
    }

    #[test]
    fn decodes_credentials_and_never_prints_them() {
        let proxy = UpstreamProxy::parse("socks5h://al%40ice:s%3Acret@p.example:1080").unwrap();
        assert_eq!(
            proxy.credentials,
            Some(("al@ice".to_owned(), "s:cret".to_owned()))
        );
        let shown = format!("{proxy} {proxy:?}");
        assert!(!shown.contains("cret") && !shown.contains("ice"), "{shown}");

        let err = UpstreamProxy::parse("http://user:secret@:bad").unwrap_err();
        assert!(!format!("{err:#}").contains("secret"));
    }

    /// Serves one HTTP proxy connection. Replies `status` to CONNECT, and if that is a success
    /// echoes what the client sends afterwards. Returns the address and the received request.
    async fn spawn_http_proxy(
        status: &'static str,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            stream
                .write_all(format!("HTTP/1.1 {status}\r\nX-Test: 1\r\n\r\nleftover").as_bytes())
                .await
                .unwrap();
            if status.starts_with('2') {
                let mut buffer = [0_u8; 4];
                stream.read_exact(&mut buffer).await.unwrap();
                stream.write_all(&buffer).await.unwrap();
            }
            String::from_utf8(request).unwrap()
        });
        (addr, task)
    }

    #[tokio::test]
    async fn http_proxy_tunnels_with_connect_and_credentials() {
        let (addr, request) = spawn_http_proxy("200 Connection Established").await;
        let proxy = UpstreamProxy::parse(&format!("http://alice:secret@{addr}")).unwrap();

        let mut stream = proxy.connect("gateway.example", 443).await.unwrap();
        // The bytes after the response header belong to the tunnel and must not be swallowed.
        let mut leftover = [0_u8; 8];
        stream.read_exact(&mut leftover).await.unwrap();
        assert_eq!(&leftover, b"leftover");
        stream.write_all(b"ping").await.unwrap();
        let mut echoed = [0_u8; 4];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");

        let request = request.await.unwrap();
        assert!(request.starts_with("CONNECT gateway.example:443 HTTP/1.1\r\n"));
        assert!(request.contains("Host: gateway.example:443\r\n"));
        assert!(request.contains("Proxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n"));
    }

    #[tokio::test]
    async fn http_proxy_refusal_is_reported_without_credentials() {
        let (addr, _request) = spawn_http_proxy("407 Proxy Authentication Required").await;
        let proxy = UpstreamProxy::parse(&format!("http://alice:secret@{addr}")).unwrap();

        let err = proxy.connect("gateway.example", 443).await.unwrap_err();
        let message = err.to_string();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(message.contains("requires authentication"), "{message}");
        assert!(!message.contains("secret"), "{message}");

        let (addr, _request) = spawn_http_proxy("403 Forbidden").await;
        let proxy = UpstreamProxy::parse(&format!("http://{addr}")).unwrap();
        let message = proxy
            .connect("gateway.example", 443)
            .await
            .unwrap_err()
            .to_string();
        assert!(message.contains("403 Forbidden"), "{message}");
    }

    /// A SOCKS5 proxy that accepts one connection, checks the greeting, optionally the password
    /// and reports the requested target as `(address type, address, port)`.
    async fn spawn_socks_proxy(
        password: Option<(&'static str, &'static str)>,
    ) -> (
        std::net::SocketAddr,
        tokio::task::JoinHandle<(u8, String, u16)>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0_u8; 2];
            stream.read_exact(&mut greeting).await.unwrap();
            let mut methods = vec![0_u8; greeting[1] as usize];
            stream.read_exact(&mut methods).await.unwrap();
            if let Some((username, secret)) = password {
                assert!(methods.contains(&2), "the password method is offered");
                stream.write_all(&[5, 2]).await.unwrap();
                let mut header = [0_u8; 2];
                stream.read_exact(&mut header).await.unwrap();
                let mut user = vec![0_u8; header[1] as usize];
                stream.read_exact(&mut user).await.unwrap();
                let mut length = [0_u8; 1];
                stream.read_exact(&mut length).await.unwrap();
                let mut pass = vec![0_u8; length[0] as usize];
                stream.read_exact(&mut pass).await.unwrap();
                assert_eq!(
                    (user.as_slice(), pass.as_slice()),
                    (username.as_bytes(), secret.as_bytes())
                );
                stream.write_all(&[1, 0]).await.unwrap();
            } else {
                stream.write_all(&[5, 0]).await.unwrap();
            }

            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..2], &[5, 1]);
            let (kind, address) = match request[3] {
                1 => {
                    let mut octets = [0_u8; 4];
                    stream.read_exact(&mut octets).await.unwrap();
                    (1, std::net::Ipv4Addr::from(octets).to_string())
                }
                4 => {
                    let mut octets = [0_u8; 16];
                    stream.read_exact(&mut octets).await.unwrap();
                    (4, std::net::Ipv6Addr::from(octets).to_string())
                }
                3 => {
                    let mut length = [0_u8; 1];
                    stream.read_exact(&mut length).await.unwrap();
                    let mut name = vec![0_u8; length[0] as usize];
                    stream.read_exact(&mut name).await.unwrap();
                    (3, String::from_utf8(name).unwrap())
                }
                other => panic!("unexpected address type {other}"),
            };
            let mut port = [0_u8; 2];
            stream.read_exact(&mut port).await.unwrap();
            stream
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut buffer = [0_u8; 4];
            stream.read_exact(&mut buffer).await.unwrap();
            stream.write_all(&buffer).await.unwrap();
            (kind, address, u16::from_be_bytes(port))
        });
        (addr, task)
    }

    #[tokio::test]
    async fn socks5h_sends_the_hostname_to_the_proxy() {
        let (addr, target) = spawn_socks_proxy(Some(("alice", "secret"))).await;
        let proxy = UpstreamProxy::parse(&format!("socks5h://alice:secret@{addr}")).unwrap();

        let mut stream = proxy.connect("gateway.example", 8443).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut echoed = [0_u8; 4];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");

        assert_eq!(
            target.await.unwrap(),
            (3, "gateway.example".to_owned(), 8443)
        );
    }

    #[tokio::test]
    async fn socks5_resolves_the_hostname_locally() {
        let (addr, target) = spawn_socks_proxy(None).await;
        let proxy = UpstreamProxy::parse(&format!("socks5://{addr}")).unwrap();

        let mut stream = proxy.connect("localhost", 8443).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut echoed = [0_u8; 4];
        stream.read_exact(&mut echoed).await.unwrap();

        // An address (IPv4 or IPv6) and not the name: it was resolved before the proxy was asked.
        let (kind, _, port) = target.await.unwrap();
        assert!(matches!(kind, 1 | 4), "address type {kind}");
        assert_eq!(port, 8443);
    }

    #[tokio::test]
    async fn an_unreachable_proxy_is_an_error_naming_it() {
        let addr = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let proxy = UpstreamProxy::parse(&format!("socks5h://u:p@{addr}")).unwrap();

        let err = proxy.connect("gateway.example", 443).await.unwrap_err();
        let message = err.to_string();
        assert!(message.contains(&format!("socks5h://{addr}")), "{message}");
        assert!(message.contains("cannot reach the proxy"), "{message}");
        assert!(message.contains("refused"), "{message}");
        assert!(!message.contains(":p@"), "{message}");
    }
}
