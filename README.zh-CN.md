# ws2tcp-local-core

`ws2tcp-local` 的核心 Rust 库。

这个 crate 包含代理服务、配置解析、路由规则、网关处理、TLS 设置，以及
TCP/WebSocket 隧道实现，供 CLI、FFI 和 GUI 前端复用。

## 用法

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

## 许可证

MIT。见 [`LICENSE`](LICENSE)。
