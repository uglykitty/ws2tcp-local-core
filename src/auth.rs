use anyhow::{Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};

fn build_basic_auth_header(credential: String) -> Result<String> {
    if !credential.contains(':') {
        bail!("--basic-auth must be formatted as user:pass");
    }

    Ok(format!("Basic {}", STANDARD.encode(credential)))
}

pub(crate) fn remote_basic_auth(cli_value: Option<String>) -> Result<Option<String>> {
    cli_value
        .or_else(|| std::env::var("WS2TCP_LOCAL_BASIC_AUTH").ok())
        .map(build_basic_auth_header)
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_basic_auth_header() {
        assert_eq!(
            build_basic_auth_header("user:pass".to_owned()).unwrap(),
            "Basic dXNlcjpwYXNz"
        );
    }

    #[test]
    fn rejects_basic_auth_without_colon() {
        assert!(build_basic_auth_header("user".to_owned()).is_err());
    }
}
