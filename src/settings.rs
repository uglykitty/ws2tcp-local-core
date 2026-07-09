use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;

pub const DEFAULT_BUFFER_SIZE: usize = 16 * 1024;
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8000";
pub const DEFAULT_RULE_REFRESH_INTERVAL_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyMode {
    Auto,
    Global,
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub listen: SocketAddr,
    pub gateway: String,
    pub basic_auth: Option<String>,
    pub buffer_size: usize,
    pub log_level: Option<String>,
    pub custom_domain_rules: Option<PathBuf>,
    pub rule_refresh_interval: Duration,
    pub proxy_mode: ProxyMode,
    pub verify_server_certificate: bool,
}

#[derive(Debug, Default, Deserialize)]
struct FileSettings {
    listen: Option<SocketAddr>,
    gateway: Option<String>,
    basic_auth: Option<String>,
    buffer_size: Option<usize>,
    log_level: Option<String>,
    custom_domain_rules: Option<PathBuf>,
    rule_refresh_interval_secs: Option<u64>,
    proxy_mode: Option<ProxyMode>,
    verify_server_certificate: Option<bool>,
}

#[derive(Debug, Default)]
pub struct SettingsOverrides {
    pub config: Option<PathBuf>,
    pub listen: Option<SocketAddr>,
    pub gateway: Option<String>,
    pub basic_auth: Option<String>,
    pub buffer_size: Option<usize>,
    pub log_level: Option<String>,
    pub custom_domain_rules: Option<PathBuf>,
    pub rule_refresh_interval_secs: Option<u64>,
    pub proxy_mode: Option<ProxyMode>,
    pub verify_server_certificate: bool,
}

impl Settings {
    pub fn resolve(overrides: SettingsOverrides) -> Result<Self> {
        let (file_settings, config_dir) = match &overrides.config {
            Some(path) => (
                read_file_settings(path)?,
                path.parent().map(Path::to_path_buf),
            ),
            None => (FileSettings::default(), None),
        };

        let listen = overrides
            .listen
            .or(file_settings.listen)
            .or_else(|| DEFAULT_LISTEN.parse().ok())
            .ok_or_else(|| anyhow!("invalid default listen address {DEFAULT_LISTEN}"))?;
        let gateway = overrides
            .gateway
            .or(file_settings.gateway)
            .ok_or_else(|| anyhow!("--gateway is required unless provided by --config"))?;
        let buffer_size = overrides
            .buffer_size
            .or(file_settings.buffer_size)
            .unwrap_or(DEFAULT_BUFFER_SIZE);
        if buffer_size == 0 {
            bail!("--buffer-size must be greater than 0");
        }
        let rule_refresh_interval_secs = overrides
            .rule_refresh_interval_secs
            .or(file_settings.rule_refresh_interval_secs)
            .unwrap_or(DEFAULT_RULE_REFRESH_INTERVAL_SECS);
        if rule_refresh_interval_secs == 0 {
            bail!("--rule-refresh-interval-secs must be greater than 0");
        }

        Ok(Self {
            listen,
            gateway,
            basic_auth: overrides.basic_auth.or(file_settings.basic_auth),
            buffer_size,
            log_level: overrides.log_level.or(file_settings.log_level),
            custom_domain_rules: overrides.custom_domain_rules.or_else(|| {
                file_settings
                    .custom_domain_rules
                    .map(|path| resolve_config_relative_path(path, config_dir.as_deref()))
            }),
            rule_refresh_interval: Duration::from_secs(rule_refresh_interval_secs),
            proxy_mode: overrides
                .proxy_mode
                .or(file_settings.proxy_mode)
                .unwrap_or(ProxyMode::Global),
            verify_server_certificate: if overrides.verify_server_certificate {
                true
            } else {
                file_settings.verify_server_certificate.unwrap_or(false)
            },
        })
    }
}

fn resolve_config_relative_path(path: PathBuf, config_dir: Option<&Path>) -> PathBuf {
    if path.is_absolute() {
        return path;
    }

    match config_dir {
        Some(dir) => dir.join(path),
        None => path,
    }
}

fn read_file_settings(path: &Path) -> Result<FileSettings> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read config file {}", path.display()))?;
    toml::from_str(&contents)
        .with_context(|| format!("failed to parse config file {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overrides_with_config(config: Option<std::path::PathBuf>) -> SettingsOverrides {
        SettingsOverrides {
            config,
            listen: None,
            gateway: None,
            basic_auth: None,
            buffer_size: None,
            log_level: None,
            custom_domain_rules: None,
            rule_refresh_interval_secs: None,
            proxy_mode: None,
            verify_server_certificate: false,
        }
    }

    #[test]
    fn rejects_missing_gateway() {
        assert!(Settings::resolve(overrides_with_config(None)).is_err());
    }

    #[test]
    fn resolves_cli_only_settings() {
        let settings = Settings::resolve(SettingsOverrides {
            config: None,
            listen: Some("127.0.0.1:9000".parse().unwrap()),
            gateway: Some("wss://example.com/ws".to_owned()),
            basic_auth: Some("user:pass".to_owned()),
            buffer_size: Some(4096),
            log_level: Some("debug".to_owned()),
            custom_domain_rules: Some("cli-domains.txt".into()),
            rule_refresh_interval_secs: Some(30),
            proxy_mode: Some(ProxyMode::Global),
            verify_server_certificate: true,
        })
        .unwrap();

        assert_eq!(settings.listen, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(settings.gateway, "wss://example.com/ws");
        assert_eq!(settings.basic_auth.as_deref(), Some("user:pass"));
        assert_eq!(settings.buffer_size, 4096);
        assert_eq!(settings.log_level.as_deref(), Some("debug"));
        assert_eq!(
            settings.custom_domain_rules.as_deref(),
            Some(Path::new("cli-domains.txt"))
        );
        assert_eq!(settings.rule_refresh_interval, Duration::from_secs(30));
        assert_eq!(settings.proxy_mode, ProxyMode::Global);
        assert!(settings.verify_server_certificate);
    }

    #[test]
    fn cli_overrides_file_settings() {
        let config_path = std::env::temp_dir().join(format!(
            "ws2tcp-local-test-{}-{}.toml",
            std::process::id(),
            "cli-overrides"
        ));
        fs::write(
            &config_path,
            r#"
listen = "127.0.0.1:8000"
gateway = "wss://file.example/ws"
basic_auth = "file:secret"
buffer_size = 1024
log_level = "info"
custom_domain_rules = "file-domains.txt"
rule_refresh_interval_secs = 45
proxy_mode = "auto"
verify_server_certificate = true
"#,
        )
        .unwrap();

        let settings = Settings::resolve(SettingsOverrides {
            config: Some(config_path.clone()),
            listen: Some("127.0.0.1:9000".parse().unwrap()),
            gateway: Some("wss://cli.example/ws".to_owned()),
            basic_auth: Some("cli:secret".to_owned()),
            buffer_size: Some(2048),
            log_level: Some("debug".to_owned()),
            custom_domain_rules: Some("cli-domains.txt".into()),
            rule_refresh_interval_secs: Some(30),
            proxy_mode: Some(ProxyMode::Global),
            verify_server_certificate: false,
        })
        .unwrap();
        let _ = fs::remove_file(&config_path);

        assert_eq!(settings.listen, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(settings.gateway, "wss://cli.example/ws");
        assert_eq!(settings.basic_auth.as_deref(), Some("cli:secret"));
        assert_eq!(settings.buffer_size, 2048);
        assert_eq!(settings.log_level.as_deref(), Some("debug"));
        assert_eq!(
            settings.custom_domain_rules.as_deref(),
            Some(Path::new("cli-domains.txt"))
        );
        assert_eq!(settings.rule_refresh_interval, Duration::from_secs(30));
        assert_eq!(settings.proxy_mode, ProxyMode::Global);
        assert!(settings.verify_server_certificate);
    }

    #[test]
    fn resolves_file_only_settings() {
        let config_path = std::env::temp_dir().join(format!(
            "ws2tcp-local-test-{}-{}.toml",
            std::process::id(),
            "file-only"
        ));
        fs::write(
            &config_path,
            r#"
listen = "127.0.0.1:7000"
gateway = "wss://file.example/ws"
buffer_size = 8192
log_level = "info"
custom_domain_rules = "custom-domains.txt"
rule_refresh_interval_secs = 45
proxy_mode = "global"
verify_server_certificate = true
"#,
        )
        .unwrap();

        let settings = Settings::resolve(overrides_with_config(Some(config_path.clone()))).unwrap();
        let _ = fs::remove_file(&config_path);

        assert_eq!(settings.listen, "127.0.0.1:7000".parse().unwrap());
        assert_eq!(settings.gateway, "wss://file.example/ws");
        assert_eq!(settings.basic_auth, None);
        assert_eq!(settings.buffer_size, 8192);
        assert_eq!(settings.log_level.as_deref(), Some("info"));
        assert_eq!(
            settings.custom_domain_rules.as_deref(),
            Some(config_path.with_file_name("custom-domains.txt").as_path())
        );
        assert_eq!(settings.rule_refresh_interval, Duration::from_secs(45));
        assert_eq!(settings.proxy_mode, ProxyMode::Global);
        assert!(settings.verify_server_certificate);
    }

    #[test]
    fn disables_server_certificate_verification_by_default() {
        let settings = Settings::resolve(SettingsOverrides {
            config: None,
            listen: None,
            gateway: Some("wss://example.com/ws".to_owned()),
            basic_auth: None,
            buffer_size: None,
            log_level: None,
            custom_domain_rules: None,
            rule_refresh_interval_secs: None,
            proxy_mode: None,
            verify_server_certificate: false,
        })
        .unwrap();

        assert!(!settings.verify_server_certificate);
    }

    #[test]
    fn uses_global_proxy_mode_by_default() {
        let settings = Settings::resolve(SettingsOverrides {
            config: None,
            listen: None,
            gateway: Some("wss://example.com/ws".to_owned()),
            basic_auth: None,
            buffer_size: None,
            log_level: None,
            custom_domain_rules: None,
            rule_refresh_interval_secs: None,
            proxy_mode: None,
            verify_server_certificate: false,
        })
        .unwrap();

        assert_eq!(settings.proxy_mode, ProxyMode::Global);
    }

    #[test]
    fn uses_default_rule_refresh_interval() {
        let settings = Settings::resolve(SettingsOverrides {
            config: None,
            listen: None,
            gateway: Some("wss://example.com/ws".to_owned()),
            basic_auth: None,
            buffer_size: None,
            log_level: None,
            custom_domain_rules: None,
            rule_refresh_interval_secs: None,
            proxy_mode: None,
            verify_server_certificate: false,
        })
        .unwrap();

        assert_eq!(
            settings.rule_refresh_interval,
            Duration::from_secs(DEFAULT_RULE_REFRESH_INTERVAL_SECS)
        );
    }

    #[test]
    fn rejects_zero_rule_refresh_interval() {
        assert!(
            Settings::resolve(SettingsOverrides {
                config: None,
                listen: None,
                gateway: Some("wss://example.com/ws".to_owned()),
                basic_auth: None,
                buffer_size: None,
                log_level: None,
                custom_domain_rules: None,
                rule_refresh_interval_secs: Some(0),
                proxy_mode: None,
                verify_server_certificate: false,
            })
            .is_err()
        );
    }
}
