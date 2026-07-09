use anyhow::{Context, Result, anyhow, bail};
use tokio::{io::AsyncReadExt, net::TcpStream};
use url::Url;

const MAX_HEADER_BYTES: usize = 16 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ProxyRequest {
    Connect {
        authority: String,
        initial_client_bytes: Vec<u8>,
    },
    Http {
        authority: String,
        initial_client_bytes: Vec<u8>,
    },
}

impl ProxyRequest {
    pub(crate) fn authority(&self) -> &str {
        match self {
            Self::Connect { authority, .. } | Self::Http { authority, .. } => authority,
        }
    }

    pub(crate) fn initial_client_bytes(self) -> Vec<u8> {
        match self {
            Self::Connect {
                initial_client_bytes,
                ..
            }
            | Self::Http {
                initial_client_bytes,
                ..
            } => initial_client_bytes,
        }
    }

    pub(crate) fn is_connect(&self) -> bool {
        matches!(self, Self::Connect { .. })
    }

    pub(crate) fn log_kind(&self) -> &'static str {
        match self {
            Self::Connect { .. } => "connect",
            Self::Http { .. } => "http",
        }
    }
}

pub(crate) async fn read_proxy_request(client: &mut TcpStream) -> Result<ProxyRequest> {
    let mut buffer = Vec::with_capacity(1024);
    let header_end = loop {
        let mut chunk = [0_u8; 1024];
        let n = client
            .read(&mut chunk)
            .await
            .context("read client request failed")?;
        if n == 0 {
            bail!("client closed before sending proxy request");
        }
        buffer.extend_from_slice(&chunk[..n]);
        if buffer.len() > MAX_HEADER_BYTES {
            bail!("proxy request header exceeds {MAX_HEADER_BYTES} bytes");
        }
        if let Some(pos) = find_header_end(&buffer) {
            break pos;
        }
    };

    let header = std::str::from_utf8(&buffer[..header_end])
        .context("proxy request header is not valid UTF-8")?;
    let leftover = buffer[header_end + 4..].to_vec();

    parse_proxy_request(header, leftover)
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_proxy_request(header: &str, leftover: Vec<u8>) -> Result<ProxyRequest> {
    let request_line = header
        .lines()
        .next()
        .ok_or_else(|| anyhow!("proxy request is empty"))?;
    let (method, target, version) = parse_request_line(request_line)?;

    if !version.starts_with("HTTP/") {
        bail!("invalid HTTP version {version}");
    }

    if method == "CONNECT" {
        validate_authority(target)?;
        return Ok(ProxyRequest::Connect {
            authority: target.to_owned(),
            initial_client_bytes: leftover,
        });
    }

    parse_http_proxy_request(header, method, target, version, leftover)
}

fn parse_request_line(request_line: &str) -> Result<(&str, &str, &str)> {
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow!("proxy request has no method"))?;
    let target = parts
        .next()
        .ok_or_else(|| anyhow!("proxy request has no target"))?;
    let version = parts
        .next()
        .ok_or_else(|| anyhow!("proxy request has no HTTP version"))?;

    if parts.next().is_some() {
        bail!("proxy request line has too many fields");
    }

    Ok((method, target, version))
}

fn parse_http_proxy_request(
    header: &str,
    method: &str,
    target: &str,
    version: &str,
    leftover: Vec<u8>,
) -> Result<ProxyRequest> {
    let (authority, origin_form) = if target.starts_with("http://")
        || target.starts_with("https://")
    {
        parse_absolute_http_target(target)?
    } else {
        let host = find_header_value(header, "host")
            .ok_or_else(|| anyhow!("HTTP proxy request without absolute URI must include Host"))?;
        (normalize_http_authority(host)?, target.to_owned())
    };
    validate_authority(&authority)?;

    let rewritten = rewrite_http_proxy_header(header, method, &origin_form, version, &authority)?;
    let mut initial_client_bytes = rewritten.into_bytes();
    initial_client_bytes.extend_from_slice(&leftover);

    Ok(ProxyRequest::Http {
        authority,
        initial_client_bytes,
    })
}

fn parse_absolute_http_target(target: &str) -> Result<(String, String)> {
    let url = Url::parse(target).with_context(|| format!("invalid HTTP proxy target: {target}"))?;
    if url.scheme() != "http" {
        bail!("ordinary HTTP proxy requests only support http:// targets; use CONNECT for https");
    }
    if url.username() != "" || url.password().is_some() {
        bail!("HTTP proxy target must not include userinfo");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("HTTP proxy target must include host"))?;
    let port = url.port_or_known_default().unwrap_or(80);
    let authority = format_authority(host, port);
    let mut origin_form = url.path().to_owned();
    if origin_form.is_empty() {
        origin_form.push('/');
    }
    if let Some(query) = url.query() {
        origin_form.push('?');
        origin_form.push_str(query);
    }

    Ok((authority, origin_form))
}

fn rewrite_http_proxy_header(
    header: &str,
    method: &str,
    origin_form: &str,
    version: &str,
    authority: &str,
) -> Result<String> {
    let mut rewritten = String::new();
    rewritten.push_str(method);
    rewritten.push(' ');
    rewritten.push_str(origin_form);
    rewritten.push(' ');
    rewritten.push_str(version);
    rewritten.push_str("\r\n");

    for line in header.lines().skip(1) {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            bail!("invalid HTTP header line");
        };
        let name = name.trim();
        if should_strip_http_proxy_header(name) {
            continue;
        }
        if name.eq_ignore_ascii_case("host") {
            rewritten.push_str("Host: ");
            rewritten.push_str(authority);
            rewritten.push_str("\r\n");
            continue;
        }
        rewritten.push_str(name);
        rewritten.push(':');
        rewritten.push_str(value);
        rewritten.push_str("\r\n");
    }

    if find_header_value(header, "host").is_none() {
        rewritten.push_str("Host: ");
        rewritten.push_str(authority);
        rewritten.push_str("\r\n");
    }
    rewritten.push_str("Connection: close\r\n\r\n");

    Ok(rewritten)
}

fn should_strip_http_proxy_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-authenticate")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("upgrade")
}

fn find_header_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.lines().skip(1).find_map(|line| {
        let (header_name, value) = line.split_once(':')?;
        header_name
            .trim()
            .eq_ignore_ascii_case(name)
            .then_some(value.trim())
    })
}

fn normalize_http_authority(host: &str) -> Result<String> {
    let host = host.trim();
    if host.is_empty() {
        bail!("HTTP Host header must not be empty");
    }
    if let Some(rest) = host.strip_prefix('[') {
        if let Some((ipv6_host, port)) = rest.split_once("]:") {
            parse_port(port)?;
            return Ok(format!("[{ipv6_host}]:{port}"));
        }
        let ipv6_host = rest
            .strip_suffix(']')
            .ok_or_else(|| anyhow!("invalid IPv6 HTTP Host header"))?;
        return Ok(format!("[{ipv6_host}]:80"));
    }
    if let Some((host_part, port)) = host.rsplit_once(':') {
        if host_part.contains(':') {
            bail!("IPv6 HTTP Host header must use [host]:port");
        }
        parse_port(port)?;
        return Ok(format!("{host_part}:{port}"));
    }
    if host.contains(':') {
        bail!("IPv6 HTTP Host header must use [host]:port");
    }

    Ok(format!("{host}:80"))
}

fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn validate_authority(authority: &str) -> Result<()> {
    if authority.is_empty() {
        bail!("empty CONNECT authority");
    }
    if authority.contains('/') || authority.contains('@') || authority.contains(char::is_whitespace)
    {
        bail!("CONNECT authority must be host:port");
    }

    if let Some(rest) = authority.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .ok_or_else(|| anyhow!("IPv6 CONNECT authority must be [host]:port"))?;
        if host.is_empty() || port.is_empty() {
            bail!("CONNECT authority host and port must be non-empty");
        }
        parse_port(port)?;
        return Ok(());
    }

    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("CONNECT authority must include :port"))?;
    if host.is_empty() || port.is_empty() {
        bail!("CONNECT authority host and port must be non-empty");
    }
    if host.contains(':') {
        bail!("IPv6 CONNECT authority must use [host]:port");
    }
    parse_port(port)?;

    Ok(())
}

fn parse_port(port: &str) -> Result<()> {
    port.parse::<u16>()
        .with_context(|| format!("invalid CONNECT authority port {port}"))?;
    Ok(())
}

#[cfg(test)]
fn parse_connect_authority(header: &str) -> Result<String> {
    match parse_proxy_request(header, Vec::new())? {
        ProxyRequest::Connect { authority, .. } => Ok(authority),
        ProxyRequest::Http { .. } => bail!("request is not CONNECT"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_authority() {
        let header = "CONNECT www.google.com:443 HTTP/1.1\r\nHost: www.google.com:443\r\n";

        assert_eq!(
            parse_connect_authority(header).unwrap(),
            "www.google.com:443"
        );
    }

    #[test]
    fn parses_ipv6_connect_authority() {
        let header = "CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n";

        assert_eq!(
            parse_connect_authority(header).unwrap(),
            "[2001:db8::1]:443"
        );
    }

    #[test]
    fn parses_http_proxy_request() {
        let header = "GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n";

        assert_eq!(
            parse_proxy_request(header, Vec::new()).unwrap(),
            ProxyRequest::Http {
                authority: "example.com:80".to_owned(),
                initial_client_bytes:
                    b"GET /path?q=1 HTTP/1.1\r\nHost: example.com:80\r\nConnection: close\r\n\r\n"
                        .to_vec(),
            }
        );
    }

    #[test]
    fn parses_http_proxy_request_with_body_leftover() {
        let header =
            "POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n";

        assert_eq!(
            parse_proxy_request(header, b"test".to_vec()).unwrap(),
            ProxyRequest::Http {
                authority: "example.com:80".to_owned(),
                initial_client_bytes: b"POST /upload HTTP/1.1\r\nHost: example.com:80\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest".to_vec(),
            }
        );
    }

    #[test]
    fn parses_origin_form_http_request_with_host_header() {
        let header = "GET /path HTTP/1.1\r\nHost: example.com:8080\r\n";

        assert_eq!(
            parse_proxy_request(header, Vec::new()).unwrap(),
            ProxyRequest::Http {
                authority: "example.com:8080".to_owned(),
                initial_client_bytes:
                    b"GET /path HTTP/1.1\r\nHost: example.com:8080\r\nConnection: close\r\n\r\n"
                        .to_vec(),
            }
        );
    }

    #[test]
    fn rejects_https_absolute_http_proxy_request() {
        let header = "GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n";

        assert!(parse_proxy_request(header, Vec::new()).is_err());
    }

    #[test]
    fn rejects_unbracketed_ipv6_authority() {
        let header = "CONNECT 2001:db8::1:443 HTTP/1.1\r\nHost: 2001:db8::1:443\r\n";

        assert!(parse_connect_authority(header).is_err());
    }
}
