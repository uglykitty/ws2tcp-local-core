# Changelog

## 0.1.6 - 2026-09-09

### Added

- Added an optional local SOCKS5 listener (`Settings.socks_listen`), sharing
  the same gateway, routing rules, and proxy mode as the existing HTTP
  listener. Only the no-authentication SOCKS5 method is supported;
  domain-name targets (ATYP 0x03) are forwarded as hostnames rather than
  resolved locally, matching `socks5h` semantics. Disabled unless
  `socks_listen` is set.

## 0.1.5 - 2026-09-07

### Removed

- Removed `init_logging` and the `tracing-subscriber` dependency. This crate
  is embedded by multiple frontends (CLI, FFI, GUI) that each need their own
  logging setup (stdout, systemd journal, an FFI callback, ...), so installing
  a global `tracing` subscriber does not belong in a shared library. Callers
  should initialize their own subscriber before invoking `run_proxy`.

## 0.1.4 - 2026-09-05

### Changed

- Download gfwlist from the primary mirror
  `https://wangguofang.net/raw.githubusercontent.com/gfwlist/gfwlist/refs/heads/master/gfwlist.txt`
  first, falling back to `https://gitlab.com/gfwlist/gfwlist/raw/master/gfwlist.txt`
  when the primary URL is unreachable.

## 0.1.3 - 2026-08-24

### Changed

- Replaced `verify_server_certificate` with the curl-style `insecure` setting.
- Enabled TLS server certificate verification by default and use the insecure
  connector only when explicitly requested.

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
