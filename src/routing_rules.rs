use std::{
    collections::HashSet,
    fs::{self, FileTimes, OpenOptions},
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{
    Client,
    header::{HeaderMap, LAST_MODIFIED},
};
use tracing::{info, warn};

use crate::settings::ProxyMode;

const GFWLIST_URL: &str = "https://gitlab.com/gfwlist/gfwlist/raw/master/gfwlist.txt";
const CACHE_DIR_NAME: &str = "ws2tcp-local";
const GFWLIST_CACHE_FILE: &str = "gfwlist.txt";

#[derive(Debug, Clone)]
pub(crate) struct RoutingRules {
    state: Arc<RwLock<RoutingRulesState>>,
    generation: Arc<AtomicU64>,
    custom_domain_rules: Option<PathBuf>,
    refresh_interval: Duration,
}

#[derive(Debug, Clone)]
enum RoutingRulesState {
    Domains {
        rules: DomainRules,
        custom_domain_rules: Option<PathBuf>,
    },
    GlobalProxy,
    DirectFallback,
}

impl RoutingRules {
    pub(crate) async fn load(
        proxy_mode: ProxyMode,
        custom_domain_rules: Option<&Path>,
        refresh_interval: Duration,
    ) -> Self {
        if proxy_mode == ProxyMode::Global {
            info!("using global proxy mode; skipping proxy routing rule download");
            return Self::new(
                RoutingRulesState::GlobalProxy,
                custom_domain_rules.map(Path::to_path_buf),
                refresh_interval,
            );
        }

        let mut loader = AutoRuleLoader::new(custom_domain_rules.map(Path::to_path_buf));
        let state = match loader.load_state().await {
            Ok(state) => state,
            Err(err) => {
                warn!(
                    url = GFWLIST_URL,
                    custom_domain_rules = custom_domain_rules.map(|path| path.display().to_string()),
                    error = %format_args!("{err:#}"),
                    "failed to load proxy routing rules; direct routing until rules are available"
                );
                RoutingRulesState::DirectFallback
            }
        };
        let rules = Self::new(
            state,
            custom_domain_rules.map(Path::to_path_buf),
            refresh_interval,
        );
        rules.spawn_auto_refresh(loader, refresh_interval, 0);
        rules
    }

    fn new(
        state: RoutingRulesState,
        custom_domain_rules: Option<PathBuf>,
        refresh_interval: Duration,
    ) -> Self {
        Self {
            state: Arc::new(RwLock::new(state)),
            generation: Arc::new(AtomicU64::new(0)),
            custom_domain_rules,
            refresh_interval,
        }
    }

    fn spawn_auto_refresh(
        &self,
        mut loader: AutoRuleLoader,
        refresh_interval: Duration,
        generation: u64,
    ) {
        let state = Arc::clone(&self.state);
        let current_generation = Arc::clone(&self.generation);

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(refresh_interval).await;
                if current_generation.load(Ordering::Acquire) != generation {
                    return;
                }

                match loader.load_state().await {
                    Ok(next_state) => {
                        if current_generation.load(Ordering::Acquire) != generation {
                            return;
                        }
                        let mut guard = state.write().expect("routing rules lock poisoned");
                        *guard = next_state;
                    }
                    Err(err) => {
                        warn!(
                            url = GFWLIST_URL,
                            custom_domain_rules =
                                loader.custom_domain_rules_display(),
                            error = %format_args!("{err:#}"),
                            "failed to refresh proxy routing rules; keeping existing rules"
                        );
                    }
                }
            }
        });
    }

    pub(crate) fn set_mode(&self, mode: ProxyMode) {
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        match mode {
            ProxyMode::Global => {
                *self.state.write().expect("routing rules lock poisoned") =
                    RoutingRulesState::GlobalProxy;
                info!("proxy mode dynamically changed to global");
            }
            ProxyMode::Auto => {
                let rules = self.clone();
                tokio::spawn(async move {
                    let mut loader = AutoRuleLoader::new(rules.custom_domain_rules.clone());
                    match loader.load_state().await {
                        Ok(next_state) => {
                            if rules.generation.load(Ordering::Acquire) != generation {
                                return;
                            }
                            *rules.state.write().expect("routing rules lock poisoned") = next_state;
                            info!("proxy mode dynamically changed to auto");
                            rules.spawn_auto_refresh(loader, rules.refresh_interval, generation);
                        }
                        Err(err) => {
                            if rules.generation.load(Ordering::Acquire) != generation {
                                return;
                            }
                            *rules.state.write().expect("routing rules lock poisoned") =
                                RoutingRulesState::DirectFallback;
                            warn!(error = %format_args!("{err:#}"), "failed to switch proxy mode to auto; using direct routing")
                        }
                    }
                });
            }
        }
    }

    pub(crate) fn should_proxy_host(&self, host: &str) -> bool {
        self.state
            .read()
            .expect("routing rules lock poisoned")
            .should_proxy_host(host)
    }

    fn mode(&self) -> &'static str {
        self.state
            .read()
            .expect("routing rules lock poisoned")
            .mode()
    }

    pub(crate) fn describe(&self) -> String {
        self.state
            .read()
            .expect("routing rules lock poisoned")
            .describe()
    }
}

#[derive(Debug)]
struct AutoRuleLoader {
    custom_domain_rules: Option<PathBuf>,
    custom_cache: Option<CustomDomainRulesCache>,
    gfwlist_cache: GfwlistCache,
}

#[derive(Debug, Clone)]
struct CustomDomainRulesCache {
    modified: SystemTime,
    domains: HashSet<String>,
}

#[derive(Debug)]
enum GfwlistCache {
    Disk(PathBuf),
    Memory {
        body: Option<Vec<u8>>,
        modified: Option<SystemTime>,
    },
}

impl AutoRuleLoader {
    fn new(custom_domain_rules: Option<PathBuf>) -> Self {
        Self {
            custom_domain_rules,
            custom_cache: None,
            gfwlist_cache: GfwlistCache::new(),
        }
    }

    async fn load_state(&mut self) -> Result<RoutingRulesState> {
        let rules = self.download_and_parse().await?;
        Ok(RoutingRulesState::from_domain_rules(
            rules,
            self.custom_domain_rules.as_deref(),
        ))
    }

    async fn download_and_parse(&mut self) -> Result<DomainRules> {
        let body = self.gfwlist_cache.load_gfwlist_body().await?;

        let mut rules = parse_gfwlist(&body)?;
        if let Some(custom_domains) = self.load_custom_domain_rules()? {
            rules.extend(custom_domains);
        }

        Ok(rules)
    }

    fn load_custom_domain_rules(&mut self) -> Result<Option<HashSet<String>>> {
        let Some(path) = self.custom_domain_rules.as_deref() else {
            return Ok(None);
        };
        let modified = file_modified_time(path).with_context(|| {
            format!(
                "failed to read custom domain rules timestamp {}",
                path.display()
            )
        })?;

        if let Some(cache) = &self.custom_cache
            && system_times_match_to_second(cache.modified, modified)
        {
            info!(
                path = %path.display(),
                custom_domain_count = cache.domains.len(),
                "using cached custom proxy routing rules"
            );
            return Ok(Some(cache.domains.clone()));
        }

        let domains = read_custom_domain_rules(path)?;
        let custom_count = domains.len();
        self.custom_cache = Some(CustomDomainRulesCache {
            modified,
            domains: domains.clone(),
        });
        info!(
            path = %path.display(),
            custom_domain_count = custom_count,
            "loaded custom proxy routing rules"
        );
        Ok(Some(domains))
    }

    fn custom_domain_rules_display(&self) -> Option<String> {
        self.custom_domain_rules
            .as_ref()
            .map(|path| path.display().to_string())
    }
}

impl RoutingRulesState {
    fn from_domain_rules(rules: DomainRules, custom_domain_rules: Option<&Path>) -> Self {
        info!(
            url = GFWLIST_URL,
            custom_domain_rules = custom_domain_rules.map(|path| path.display().to_string()),
            domain_count = rules.len(),
            "loaded proxy routing rules"
        );
        Self::Domains {
            rules,
            custom_domain_rules: custom_domain_rules.map(Path::to_path_buf),
        }
    }

    fn should_proxy_host(&self, host: &str) -> bool {
        match self {
            Self::Domains { rules, .. } => rules.matches(host),
            Self::GlobalProxy => true,
            Self::DirectFallback => false,
        }
    }

    fn mode(&self) -> &'static str {
        match self {
            Self::Domains { .. } | Self::DirectFallback => "auto",
            Self::GlobalProxy => "global",
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::Domains {
                rules,
                custom_domain_rules: Some(path),
            } => format!(
                "{} domains from {} plus custom rules from {}",
                rules.len(),
                GFWLIST_URL,
                path.display()
            ),
            Self::Domains {
                rules,
                custom_domain_rules: None,
            } => format!("{} domains from {}", rules.len(), GFWLIST_URL),
            Self::GlobalProxy => "all domains via proxy; proxy mode is global".to_owned(),
            Self::DirectFallback => {
                format!("direct routing; failed to load {GFWLIST_URL}")
            }
        }
    }
}

impl GfwlistCache {
    fn new() -> Self {
        match gfwlist_cache_path().and_then(check_gfwlist_cache_access) {
            Ok(path) => Self::Disk(path),
            Err(err) => {
                warn!(
                    error = %format_args!("{err:#}"),
                    "gfwlist disk cache is unavailable; using in-memory cache"
                );
                Self::empty_memory()
            }
        }
    }

    fn empty_memory() -> Self {
        Self::Memory {
            body: None,
            modified: None,
        }
    }

    fn switch_to_memory(&mut self, error: &anyhow::Error) {
        warn!(
            error = %format_args!("{error:#}"),
            "gfwlist disk cache failed; switching to in-memory cache"
        );
        *self = Self::empty_memory();
    }

    fn memory_body_if_current(&self, remote_modified: Option<SystemTime>) -> Option<Vec<u8>> {
        let Self::Memory { body, modified } = self else {
            return None;
        };
        let remote_modified = remote_modified?;
        let cached_modified = (*modified)?;

        system_times_match_to_second(cached_modified, remote_modified)
            .then(|| body.clone())
            .flatten()
    }

    fn store_in_memory(&mut self, body: Vec<u8>, modified: Option<SystemTime>) {
        *self = Self::Memory {
            body: Some(body),
            modified,
        };
    }

    async fn load_gfwlist_body(&mut self) -> Result<Vec<u8>> {
        let client = Client::new();
        let remote_modified = fetch_remote_last_modified(&client).await?;

        if let Self::Disk(cache_path) = self {
            let cached = match remote_modified {
                Some(remote_modified) => match is_cache_current(cache_path, remote_modified) {
                    Ok(true) => Some(fs::read(&*cache_path).with_context(|| {
                        format!("failed to read cached gfwlist {}", cache_path.display())
                    })),
                    Ok(false) => None,
                    Err(err) => Some(Err(err)),
                },
                None => None,
            };

            if let Some(cached) = cached {
                match cached {
                    Ok(body) => {
                        info!(
                            cache_path = %cache_path.display(),
                            url = GFWLIST_URL,
                            "using cached gfwlist"
                        );
                        return Ok(body);
                    }
                    Err(err) => self.switch_to_memory(&err),
                }
            }
        }

        if let Some(body) = self.memory_body_if_current(remote_modified) {
            info!(url = GFWLIST_URL, "using in-memory cached gfwlist");
            return Ok(body);
        }

        let response = client
            .get(GFWLIST_URL)
            .send()
            .await
            .with_context(|| format!("failed to download {GFWLIST_URL}"))?
            .error_for_status()
            .with_context(|| format!("failed to download {GFWLIST_URL}"))?;
        let downloaded_modified = parse_last_modified(response.headers()).or(remote_modified);
        let body = response
            .bytes()
            .await
            .context("failed to read gfwlist response body")?
            .to_vec();

        if let Self::Disk(cache_path) = self
            && let Err(err) = write_gfwlist_cache(cache_path, &body, downloaded_modified)
        {
            self.switch_to_memory(&err);
        }
        if matches!(self, Self::Memory { .. }) {
            self.store_in_memory(body.clone(), downloaded_modified);
        }

        Ok(body)
    }
}

async fn fetch_remote_last_modified(client: &Client) -> Result<Option<SystemTime>> {
    let response = client
        .head(GFWLIST_URL)
        .send()
        .await
        .with_context(|| format!("failed to check remote gfwlist timestamp {GFWLIST_URL}"))?
        .error_for_status()
        .with_context(|| format!("failed to check remote gfwlist timestamp {GFWLIST_URL}"))?;

    Ok(parse_last_modified(response.headers()))
}

fn parse_last_modified(headers: &HeaderMap) -> Option<SystemTime> {
    headers
        .get(LAST_MODIFIED)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| httpdate::parse_http_date(value).ok())
}

fn gfwlist_cache_path() -> Result<PathBuf> {
    let cache_dir = user_cache_dir()?;

    Ok(cache_dir.join(CACHE_DIR_NAME).join(GFWLIST_CACHE_FILE))
}

fn check_gfwlist_cache_access(cache_path: PathBuf) -> Result<PathBuf> {
    let parent = cache_path
        .parent()
        .context("gfwlist cache path has no parent directory")?;
    fs::create_dir_all(parent).with_context(|| {
        format!(
            "failed to create gfwlist cache directory {}",
            parent.display()
        )
    })?;

    if cache_path.exists() {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&cache_path)
            .with_context(|| {
                format!(
                    "gfwlist cache is not readable and writable {}",
                    cache_path.display()
                )
            })?;
    }

    let probe_path = parent.join(format!(".cache-access-{}", std::process::id()));
    let probe_result = (|| -> Result<()> {
        let mut probe = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&probe_path)
            .with_context(|| {
                format!(
                    "gfwlist cache directory is not writable {}",
                    parent.display()
                )
            })?;
        probe.write_all(b"ok")?;
        probe.rewind()?;
        let mut contents = String::new();
        probe.read_to_string(&mut contents)?;
        if contents != "ok" {
            bail!("gfwlist cache access probe returned unexpected contents");
        }
        Ok(())
    })();
    let remove_result = fs::remove_file(&probe_path);
    probe_result?;
    remove_result.with_context(|| {
        format!(
            "failed to remove gfwlist cache access probe {}",
            probe_path.display()
        )
    })?;

    Ok(cache_path)
}

#[cfg(windows)]
fn user_cache_dir() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("LOCALAPPDATA") {
        return Ok(PathBuf::from(path));
    }

    let profile = std::env::var_os("USERPROFILE")
        .context("USERPROFILE is not set; cannot locate gfwlist cache")?;
    Ok(PathBuf::from(profile).join("AppData").join("Local"))
}

#[cfg(target_os = "macos")]
fn user_cache_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set; cannot locate gfwlist cache")?;
    Ok(PathBuf::from(home).join("Library").join("Caches"))
}

#[cfg(all(not(windows), not(target_os = "macos")))]
fn user_cache_dir() -> Result<PathBuf> {
    match std::env::var_os("XDG_CACHE_HOME") {
        Some(path) => Ok(PathBuf::from(path)),
        None => {
            let home =
                std::env::var_os("HOME").context("HOME is not set; cannot locate gfwlist cache")?;
            Ok(PathBuf::from(home).join(".cache"))
        }
    }
}

fn is_cache_current(cache_path: &Path, remote_modified: SystemTime) -> Result<bool> {
    let cache_modified = match file_modified_time(cache_path) {
        Ok(modified) => modified,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed to read gfwlist cache {}", cache_path.display()));
        }
    };

    Ok(system_times_match_to_second(
        cache_modified,
        remote_modified,
    ))
}

fn file_modified_time(path: &Path) -> std::io::Result<SystemTime> {
    fs::metadata(path)?.modified()
}

fn write_gfwlist_cache(
    cache_path: &Path,
    body: &[u8],
    remote_modified: Option<SystemTime>,
) -> Result<()> {
    if let Some(parent) = cache_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create gfwlist cache directory {}",
                parent.display()
            )
        })?;
    }

    fs::write(cache_path, body)
        .with_context(|| format!("failed to write gfwlist cache {}", cache_path.display()))?;

    if let Some(remote_modified) = remote_modified {
        fs::File::options()
            .write(true)
            .open(cache_path)
            .and_then(|file| file.set_times(FileTimes::new().set_modified(remote_modified)))
            .with_context(|| {
                format!(
                    "failed to update gfwlist cache timestamp {}",
                    cache_path.display()
                )
            })?;
    }

    info!(
        cache_path = %cache_path.display(),
        url = GFWLIST_URL,
        "updated gfwlist cache"
    );
    Ok(())
}

fn system_times_match_to_second(left: SystemTime, right: SystemTime) -> bool {
    left.duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .map(truncate_to_second)
        == right
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .map(truncate_to_second)
}

fn truncate_to_second(duration: Duration) -> Duration {
    Duration::from_secs(duration.as_secs())
}

#[derive(Debug, Clone)]
pub(crate) struct DomainRules {
    domains: HashSet<String>,
}

impl DomainRules {
    fn new(domains: HashSet<String>) -> Result<Self> {
        if domains.is_empty() {
            bail!("gfwlist did not contain any usable domain rules");
        }

        Ok(Self { domains })
    }

    fn len(&self) -> usize {
        self.domains.len()
    }

    fn extend(&mut self, domains: HashSet<String>) {
        self.domains.extend(domains);
    }

    fn matches(&self, host: &str) -> bool {
        let host = normalize_host_for_match(host);
        if host.is_empty() {
            return false;
        }

        if self.domains.contains(&host) {
            return true;
        }

        host.match_indices('.')
            .any(|(idx, _)| self.domains.contains(&host[idx + 1..]))
    }
}

fn parse_gfwlist(encoded: &[u8]) -> Result<DomainRules> {
    let compact: Vec<u8> = encoded
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    let decoded = STANDARD
        .decode(compact)
        .context("failed to decode gfwlist")?;
    let text = String::from_utf8(decoded).context("decoded gfwlist is not valid UTF-8")?;
    parse_gfwlist_text(&text)
}

fn parse_gfwlist_text(text: &str) -> Result<DomainRules> {
    let domains = text
        .lines()
        .filter_map(parse_proxy_rule_domain)
        .collect::<HashSet<_>>();

    DomainRules::new(domains)
}

fn read_custom_domain_rules(path: &Path) -> Result<HashSet<String>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read custom domain rules {}", path.display()))?;
    Ok(parse_custom_domain_rules_text(&text))
}

fn parse_custom_domain_rules_text(text: &str) -> HashSet<String> {
    text.lines()
        .filter_map(parse_custom_domain_rule_domain)
        .collect()
}

fn parse_custom_domain_rule_domain(line: &str) -> Option<String> {
    let rule = line.split('#').next().unwrap_or_default().trim();
    let domain = normalize_host_for_match(rule);
    is_domain_like(&domain).then_some(domain)
}

fn parse_proxy_rule_domain(line: &str) -> Option<String> {
    let rule = line.strip_prefix("||").or_else(|| line.strip_prefix('.'))?;
    if rule.contains('*') {
        return None;
    }

    let domain = rule
        .split(['/', '^', '$'])
        .next()
        .unwrap_or_default()
        .trim_matches('.');
    let domain = normalize_host_for_match(domain);
    is_domain_like(&domain).then_some(domain)
}

fn normalize_host_for_match(host: &str) -> String {
    host.trim().trim_matches('.').to_ascii_lowercase()
}

fn is_domain_like(domain: &str) -> bool {
    if domain.is_empty() || domain.contains(':') || domain.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }

    domain
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
}

pub(crate) fn host_from_authority(authority: &str) -> Result<&str> {
    if let Some(rest) = authority.strip_prefix('[') {
        return rest
            .split_once("]:")
            .map(|(host, _)| host)
            .ok_or_else(|| anyhow!("IPv6 authority must be [host]:port"));
    }

    authority
        .rsplit_once(':')
        .map(|(host, _)| host)
        .ok_or_else(|| anyhow!("authority must include :port"))
}

impl std::fmt::Display for RoutingRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.mode())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;

    #[test]
    fn parses_gfwlist_domain_rules() {
        let text = "\
! comment
||example.com
||example.net/path
||example.org^
||example.edu$third-party
||wild*.blocked.test
.leading-dot.example
|http://ignored.example
";
        let encoded = STANDARD.encode(text);
        let rules = parse_gfwlist(encoded.as_bytes()).unwrap();

        assert!(rules.matches("example.com"));
        assert!(rules.matches("www.example.com"));
        assert!(rules.matches("example.net"));
        assert!(rules.matches("a.example.org"));
        assert!(rules.matches("example.edu"));
        assert!(rules.matches("www.leading-dot.example"));
        assert!(!rules.matches("wild.blocked.test"));
        assert!(!rules.matches("ignored.example"));
    }

    #[test]
    fn matches_case_insensitively_and_on_suffix_boundary() {
        let rules = parse_gfwlist_text("||example.com\n").unwrap();

        assert!(rules.matches("WWW.Example.Com."));
        assert!(!rules.matches("badexample.com"));
    }

    #[test]
    fn parses_custom_domain_rules() {
        let domains = parse_custom_domain_rules_text(
            "\
# One Squid dstdomain entry per line.
.paypal.com
.www.paypal.com

.googleadservices.com # inline comment
127.0.0.1
bad:domain
",
        );
        let rules = DomainRules::new(domains).unwrap();

        assert!(rules.matches("paypal.com"));
        assert!(rules.matches("checkout.paypal.com"));
        assert!(rules.matches("www.paypal.com"));
        assert!(rules.matches("pagead.googleadservices.com"));
        assert!(!rules.matches("127.0.0.1"));
        assert!(!rules.matches("bad:domain"));
    }

    #[test]
    fn custom_domain_rules_cache_reuses_unchanged_file() {
        let path = temp_custom_rules_path("custom-cache-reuses-unchanged");
        let modified = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        write_custom_rules_at(&path, ".first.example\n", modified);
        let mut loader = AutoRuleLoader::new(Some(path.clone()));

        let first = loader.load_custom_domain_rules().unwrap().unwrap();
        write_custom_rules_at(&path, ".second.example\n", modified);
        let second = loader.load_custom_domain_rules().unwrap().unwrap();
        let _ = fs::remove_file(&path);

        assert!(first.contains("first.example"));
        assert!(second.contains("first.example"));
        assert!(!second.contains("second.example"));
    }

    #[test]
    fn custom_domain_rules_cache_reloads_changed_file() {
        let path = temp_custom_rules_path("custom-cache-reloads-changed");
        let first_modified = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let second_modified = first_modified + Duration::from_secs(2);
        write_custom_rules_at(&path, ".first.example\n", first_modified);
        let mut loader = AutoRuleLoader::new(Some(path.clone()));

        let first = loader.load_custom_domain_rules().unwrap().unwrap();
        write_custom_rules_at(&path, ".second.example\n", second_modified);
        let second = loader.load_custom_domain_rules().unwrap().unwrap();
        let _ = fs::remove_file(&path);

        assert!(first.contains("first.example"));
        assert!(!second.contains("first.example"));
        assert!(second.contains("second.example"));
    }

    #[test]
    fn parses_last_modified_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            LAST_MODIFIED,
            "Wed, 21 Oct 2015 07:28:00 GMT".parse().unwrap(),
        );

        assert_eq!(
            parse_last_modified(&headers).unwrap(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_445_412_480)
        );
    }

    #[test]
    fn compares_timestamps_to_second_precision() {
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(42);

        assert!(system_times_match_to_second(
            timestamp + Duration::from_millis(900),
            timestamp
        ));
        assert!(!system_times_match_to_second(
            timestamp + Duration::from_secs(1),
            timestamp
        ));
    }

    #[test]
    fn extracts_host_from_authority() {
        assert_eq!(
            host_from_authority("example.com:443").unwrap(),
            "example.com"
        );
        assert_eq!(
            host_from_authority("[2001:db8::1]:443").unwrap(),
            "2001:db8::1"
        );
    }

    #[test]
    fn global_proxy_matches_every_host() {
        let rules = RoutingRules::new(
            RoutingRulesState::GlobalProxy,
            None,
            Duration::from_secs(60),
        );

        assert!(rules.should_proxy_host("example.com"));
        assert_eq!(rules.to_string(), "global");
        assert_eq!(
            rules.describe(),
            "all domains via proxy; proxy mode is global"
        );
    }

    #[tokio::test]
    async fn global_proxy_load_skips_rule_files() {
        let rules = RoutingRules::load(
            ProxyMode::Global,
            Some(Path::new("/definitely/missing/custom-domains.txt")),
            Duration::from_secs(60),
        )
        .await;

        assert!(rules.should_proxy_host("example.com"));
        assert_eq!(rules.to_string(), "global");
    }

    #[test]
    fn auto_fallback_routes_direct_by_default() {
        let rules = RoutingRules::new(
            RoutingRulesState::DirectFallback,
            None,
            Duration::from_secs(60),
        );

        assert!(!rules.should_proxy_host("example.com"));
        assert_eq!(rules.to_string(), "auto");
        assert_eq!(
            rules.describe(),
            format!("direct routing; failed to load {GFWLIST_URL}")
        );
    }

    #[test]
    fn dynamically_switches_to_global_mode() {
        let rules = RoutingRules::new(
            RoutingRulesState::DirectFallback,
            None,
            Duration::from_secs(60),
        );

        rules.set_mode(ProxyMode::Global);

        assert!(rules.should_proxy_host("example.com"));
        assert_eq!(rules.to_string(), "global");
    }

    fn temp_custom_rules_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ws2tcp-local-test-{}-{name}.txt",
            std::process::id()
        ))
    }

    fn write_custom_rules_at(path: &Path, text: &str, modified: SystemTime) {
        fs::write(path, text).unwrap();
        fs::File::options()
            .write(true)
            .open(path)
            .and_then(|file| file.set_times(FileTimes::new().set_modified(modified)))
            .unwrap();
    }
}
