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

## License

MIT. See [`LICENSE`](LICENSE).
