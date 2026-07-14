# Changelog

## 0.1.2 - 2026-07-14

### Changed

- Check the platform gfwlist cache for read and write access when automatic
  routing rules start loading.
- Fall back to an in-memory gfwlist cache when the disk cache is unavailable at
  startup or fails during a later read or write.
- Keep the downloaded rules usable when disk cache access fails instead of
  falling back to direct routing.

## 0.1.5 - 2026-07-08

### Changed

- Changed auto proxy rule loading from startup-only loading to periodic hot reload.
- Added configurable rule refresh interval with `--rule-refresh-interval-secs` and `rule_refresh_interval_secs`; the default is 60 seconds.
- Kept gfwlist downloads conditional on remote `Last-Modified` changes so unchanged lists continue to use the local cache.
- Added hot reload for custom domain rules using the custom rules file modification time.
- Changed auto mode fallback behavior to route directly when rules are unavailable, while still proxying only hosts matched by loaded rules.
- Replaced active routing rules atomically on successful refresh and kept the previous active rules when refresh fails.
- Updated English and Chinese documentation plus the example TOML configuration for the new rule refresh behavior.
