use anyhow::{Context, Result, bail};
use url::Url;

#[derive(Debug, Clone)]
pub(crate) struct Gateway {
    base: String,
}

impl Gateway {
    pub(crate) fn parse(input: &str) -> Result<Self> {
        let url = Url::parse(input).with_context(|| format!("invalid gateway URL: {input}"))?;
        match url.scheme() {
            "ws" | "wss" => {}
            scheme => bail!("gateway URL scheme must be ws or wss, got {scheme}"),
        }
        if url.query().is_some() || url.fragment().is_some() {
            bail!("gateway URL must not contain query or fragment");
        }

        Ok(Self {
            base: input.trim_end_matches('/').to_owned(),
        })
    }

    pub(crate) fn base(&self) -> &str {
        &self.base
    }

    /// The gateway root, which ws2tcp-router answers with its health check.
    pub(crate) fn health_check_url(&self) -> String {
        format!("{}/", self.base)
    }

    /// A token endpoint of the router, `/auth/<endpoint>`, on the gateway origin over HTTP(S).
    pub(crate) fn auth_url(&self, endpoint: &str) -> String {
        let mut url = Url::parse(&self.base).expect("the base was validated by Gateway::parse");
        let scheme = if url.scheme() == "wss" {
            "https"
        } else {
            "http"
        };
        url.set_scheme(scheme)
            .expect("ws and wss can become http and https");
        format!("{}/auth/{endpoint}", url.as_str().trim_end_matches('/'))
    }

    pub(crate) fn target_url(&self, authority: &str) -> String {
        format!("{}/tcp:{}", self.base, authority)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_gateway_target_url() {
        let gateway = Gateway::parse("wss://1.2.3.4/gw/").unwrap();

        assert_eq!(
            gateway.target_url("www.google.com:443"),
            "wss://1.2.3.4/gw/tcp:www.google.com:443"
        );
    }

    #[test]
    fn builds_token_endpoint_urls_over_http() {
        assert_eq!(
            Gateway::parse("wss://1.2.3.4/gw/")
                .unwrap()
                .auth_url("token"),
            "https://1.2.3.4/gw/auth/token"
        );
        assert_eq!(
            Gateway::parse("ws://1.2.3.4:8000")
                .unwrap()
                .auth_url("refresh"),
            "http://1.2.3.4:8000/auth/refresh"
        );
        assert_eq!(
            Gateway::parse("WSS://Example.com")
                .unwrap()
                .auth_url("token"),
            "https://example.com/auth/token"
        );
    }

    #[test]
    fn builds_health_check_url() {
        assert_eq!(
            Gateway::parse("wss://1.2.3.4/gw/")
                .unwrap()
                .health_check_url(),
            "wss://1.2.3.4/gw/"
        );
        assert_eq!(
            Gateway::parse("ws://1.2.3.4:8000")
                .unwrap()
                .health_check_url(),
            "ws://1.2.3.4:8000/"
        );
    }
}
