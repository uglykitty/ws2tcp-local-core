# ws2tcp-local-core

Core Rust library for `ws2tcp-local`.

This crate contains the proxy service, settings resolution, routing rules,
gateway handling, TLS setup, and TCP/WebSocket tunnel implementation used by the
CLI, FFI, and GUI frontends.

## Usage

```rust
use ws2tcp_local_core::{Settings, SettingsOverrides, run_proxy};

# async fn example() -> anyhow::Result<()> {
let settings = Settings::resolve(SettingsOverrides {
    gateway: Some("wss://example.com".to_owned()),
    ..SettingsOverrides::default()
})?;

run_proxy(settings, async {}).await?;
# Ok(())
# }
```

`run_proxy` first checks the gateway (a websocket handshake on the gateway root,
answered by `ws2tcp-router`'s health check) before loading routing rules or
binding any port. When the check fails, the returned `anyhow::Error` wraps a
`GatewayCheckError`:

```rust
# async fn example(settings: ws2tcp_local_core::Settings) -> anyhow::Result<()> {
use ws2tcp_local_core::{GatewayCheckError, run_proxy};

if let Err(err) = run_proxy(settings, async {}).await {
    match err.downcast_ref::<GatewayCheckError>() {
        Some(GatewayCheckError::Unauthorized { .. }) => eprintln!("wrong credentials: {err}"),
        Some(GatewayCheckError::Failed(_)) => eprintln!("gateway unusable: {err}"),
        None => return Err(err),
    }
}
# Ok(())
# }
```

## Gateway authentication

The client authenticates to the gateway with exactly one method at a time, chosen with
`Settings::auth_mode`. The default is `Token`. `Basic` (a health check, then Basic Auth on every
connection) is kept only for compatibility with gateways that have no token authentication; it
logs a warning on startup and is to be phased out. Without credentials authentication is not
enabled: nothing is sent at startup, in either mode, and the proxy starts right away.

At startup:

```mermaid
flowchart TD
    S["run_proxy starts"] --> C{"Credentials configured?"}
    C -- no --> N["GatewayAuth::None<br/>nothing is sent, the proxy starts right away"]
    C -- yes --> M{"Settings::auth_mode"}
    M -- "Token (default)" --> L["POST /auth/token with Basic Auth<br/>no health check: the login is the check"]
    L -- "200" --> T["GatewayAuth::Token<br/>Bearer access token, renewed as needed"]
    L -- "401" --> E1["Startup fails:<br/>GatewayCheckError::Unauthorized"]
    L -- "404, 403, connection closed, anything else" --> E4["Startup fails:<br/>GatewayCheckError::LoginFailed"]
    M -- "Basic (compatibility only)" --> H["Health check with the Basic Auth credentials"]
    H -- "passes" --> B["GatewayAuth::Basic<br/>Basic Auth on every tunnel<br/>a warning says it will be phased out"]
    H -- "401" --> E1
    H -- "unreachable, not a ws2tcp-router, ..." --> E2["Startup fails:<br/>GatewayCheckError::Failed"]
```

In token mode there is no fallback to Basic Auth. A background task renews the access token on
its own once 80% of its lifetime is used, so that neither the application nor the tunnels have to
wait for it. It ends with the session, never asks more often than once a second, and after a
failure tries again after 5 seconds, doubling up to 5 minutes:

```mermaid
flowchart TD
    A["Wait until 80% of the access token's lifetime is used"] --> B{"Renewed meanwhile,<br/>for example by a tunnel?"}
    B -- yes --> A
    B -- no --> C["POST /auth/refresh,<br/>or log in again when the refresh token is refused or expired"]
    C -- ok --> A
    C -- error --> D["Warn, wait 5 s, doubling up to 5 min"]
    D --> A
```

Every tunnel still checks the token when it opens (`GatewayAuth::authorization`), as a safety
net for a renewal that failed or has not happened yet. It renews first when the token is due,
and concurrent tunnels wait for one renewal, because a refresh token can be used only once:

```mermaid
flowchart TD
    A["Tunnel request"] --> B{"Access token due?"}
    B -- no --> U["Authorization: Bearer access token"]
    B -- yes --> C{"Refresh token still valid?"}
    C -- yes --> D["POST /auth/refresh"]
    C -- no --> L["POST /auth/token with Basic Auth"]
    D -- "200" --> U
    D -- "401" --> L
    D -- "other error" --> K{"Access token still valid?"}
    L -- "200" --> U
    L -- "error" --> K
    K -- yes --> R["Use it, try to renew again in 5 s"]
    R --> U
    K -- no --> X["The tunnel request fails"]
    U --> W["WebSocket handshake with the gateway"]
    W -- "101" --> OK["Tunnel open"]
    W -- "401, first time" --> M["Mark the token as rejected"]
    M --> A
```

Tokens are never logged, and the `Authorization` header values are marked sensitive.

## License

MIT. See [`LICENSE`](LICENSE).
