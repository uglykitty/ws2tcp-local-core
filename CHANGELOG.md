# Changelog

## 0.3.0 - 2026-09-21

### Added

- `Settings::upstream_proxy` (an `UpstreamProxy`; `SettingsOverrides::upstream_proxy` and
  `upstream_proxy` in the config file) makes every connection to the gateway go through a proxy
  server: the tunnels, the health check and the token requests. `UpstreamProxy::parse` accepts
  `http://` (an HTTP proxy, used with `CONNECT`), `socks5h://` (the proxy resolves hostnames) and
  `socks5://` (hostnames are resolved locally) URLs, with optional percent-encoded `user:pass@`
  credentials. Requests that a routing rule sends direct do not use it, and the proxy environment
  variables are ignored. Logs and errors name the proxy but never show its credentials. A blank
  value means no proxy, and in `SettingsOverrides` overrides one from the file.

### Changed

- **`Settings` has a new public field, `upstream_proxy`**, so code that builds it with a struct
  literal has to set it (`None` for no proxy).

## 0.2.0 - 2026-09-20

### Added

- `Settings::auth_mode` (an `AuthMode`; also in `SettingsOverrides`, and `auth_mode` in the
  config file) chooses how the client authenticates to the gateway, one method at a time:
  - `AuthMode::Token`, the default: no health check. `run_proxy` logs in with the Basic Auth
    credentials (`POST /auth/token`, over `http(s)://` on the gateway's host, port and path
    prefix), and that login is the check. Tunnels use `Authorization: Bearer <access token>`,
    renewed with the refresh token (`POST /auth/refresh`) once 80% of its lifetime is used,
    by a background task that needs neither a tunnel nor the embedding application (it ends
    with the session, runs at most once a second, and backs off from 5 seconds to 5 minutes
    after failures); when the router refuses the refresh token (it expired, was revoked, or
    the router restarted) the client logs in again. Tunnels still check the token when they
    open, as a safety net: a token that is due is renewed first, a tunnel that the gateway
    answers with `401` renews the token and is tried once more, and concurrent tunnels share
    one renewal. There is no fallback to Basic Auth: rejected credentials fail with
    `GatewayCheckError::Unauthorized`, and any other failure to log in with the new
    `GatewayCheckError::LoginFailed`. Tokens are never logged.
  - `AuthMode::Basic`: what `run_proxy` always did, the health check and Basic Auth on every
    connection. Kept for compatibility with gateways that have no token authentication, and
    to be phased out; it logs a warning on startup.

### Changed

- **`run_proxy` sends nothing at startup without credentials.** Authentication is not enabled,
  so there is no health check and the proxy starts right away, in either mode. The health
  check now only runs in `AuthMode::Basic` with credentials.
- **The default is `AuthMode::Token`**, so a gateway without token authentication needs
  `AuthMode::Basic`.
- The health check no longer reads the `X-Ws2tcp-Token` response header, and tunnel requests no
  longer send that header: `ws2tcp-router` replaced it with the real token authentication and
  ignores it. `Authorization` header values are now marked sensitive.
- New dependency: `serde_json`.
- `Settings` and `SettingsOverrides` have a new field `auth_mode`, and `GatewayCheckError` a
  new variant `LoginFailed`: code that builds these structs or matches the enum exhaustively
  needs updating.

## 0.1.9 - 2026-09-19

### Added

- `run_proxy` and `run_proxy_with_mode_updates` now check the gateway before
  loading routing rules or binding any port: a websocket handshake on the
  gateway root, with the configured credentials, custom headers and TLS
  settings, which must answer with the `ws2tcp-router` health check message.
  On failure they return a `GatewayCheckError` inside the `anyhow::Error`
  (`downcast_ref` it): `Unauthorized { credentials_configured }` for `401`, and
  `Failed(reason)` for an unreachable gateway, a timeout (10 seconds), or a
  gateway that does not answer like `ws2tcp-router`.

- When the gateway's health check response carries an `X-Ws2tcp-Token` header,
  the token is kept for the lifetime of the proxy and sent as the same header
  on every tunnel request, next to the Basic Auth header (replacing any
  custom header of that name). It is marked sensitive and never logged. A
  gateway that sends no token is still accepted. `ws2tcp-router` does not
  verify the token yet.

### Changed

- Embedders (such as `ws2tcp-local-ffi`) now get an error from `run_proxy`
  when the gateway check fails, and need a `ws2tcp-router` that supports the
  `/` health check.

## 0.1.8 - 2026-09-19

### Added

- Added `Settings.headers` and `Settings::add_header`, letting embedding
  frontends send custom headers (for example `User-Agent`) on the gateway
  websocket handshake. Adding the same name again replaces the earlier value;
  headers owned by the websocket handshake (`Host`, `Connection`, `Upgrade`,
  `Sec-WebSocket-*`) are rejected.

### Removed

- Removed `Settings.client_label`; use `Settings::add_header("User-Agent", ..)`
  instead. gfwlist HTTP requests now send only `ws2tcp-local-core/<version>`.

## 0.1.7 - 2026-09-17

### Added

- Added `Settings.client_label`, an optional identifier for the embedding
  frontend (e.g. `cli/0.1.18`, `ws2tcp-local-qt/0.3.2`). When set, it is
  included in the `User-Agent` header sent with gfwlist HTTP requests, so the
  server can tell which frontend is making the request. Not user-configurable
  via `--config`/CLI flags; callers set it directly on `Settings` after
  `resolve()`.

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
