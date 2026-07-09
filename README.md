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

## License

MIT. See [`LICENSE`](LICENSE).
