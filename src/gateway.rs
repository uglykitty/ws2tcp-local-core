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
}
