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

## Gateway 认证

客户端同一时间只使用一种方式向 gateway 认证，由 `Settings::auth_mode` 选择，默认是 `Token`。`Basic`（健康检查，然后每个连接发送 Basic 认证）
只是为兼容没有 token 认证的 gateway 而保留，启动时会输出警告，之后会被逐步淘汰。没有认证信息表示未开启认证：两种模式下启动时都不发送任何请求，
代理直接启动。

启动时：

```mermaid
flowchart TD
    S["run_proxy 启动"] --> C{"配置了认证信息？"}
    C -- 否 --> N["GatewayAuth::None<br/>不发送任何请求，代理直接启动"]
    C -- 是 --> M{"Settings::auth_mode"}
    M -- "Token（默认）" --> L["用 Basic 认证 POST /auth/token<br/>不做健康检查：登录就是检查"]
    L -- "200" --> T["GatewayAuth::Token<br/>Bearer access token，按需续期"]
    L -- "401" --> E1["启动失败：<br/>GatewayCheckError::Unauthorized"]
    L -- "404、403、连接被关闭或其他情况" --> E4["启动失败：<br/>GatewayCheckError::LoginFailed"]
    M -- "Basic（仅为兼容）" --> H["用 Basic 认证信息做健康检查"]
    H -- "通过" --> B["GatewayAuth::Basic<br/>每个隧道发送 Basic 认证<br/>警告：该方式将被淘汰"]
    H -- "401" --> E1
    H -- "无法连接、不是 ws2tcp-router 等" --> E2["启动失败：<br/>GatewayCheckError::Failed"]
```

token 模式不会回退到 Basic 认证。后台任务会在 access token 用掉 80% 寿命时自行续期，因此应用和隧道都不必等待续期。
它随会话结束而结束，最多每秒请求一次，失败后 5 秒重试，之后每次翻倍，最长 5 分钟：

```mermaid
flowchart TD
    A["等到 access token 用掉 80% 寿命"] --> B{"期间已被续期，<br/>例如被某个隧道续期？"}
    B -- 是 --> A
    B -- 否 --> C["POST /auth/refresh，<br/>refresh token 被拒绝或过期时重新登录"]
    C -- 成功 --> A
    C -- 错误 --> D["输出警告，等待 5 秒，之后翻倍，最长 5 分钟"]
    D --> A
```

每个隧道打开时仍会检查 token（`GatewayAuth::authorization`），作为续期失败或尚未发生时的兜底：token 到期时先续期，
并发的隧道会等待同一次续期，因为 refresh token 只能使用一次：

```mermaid
flowchart TD
    A["隧道请求"] --> B{"access token 到期了？"}
    B -- 否 --> U["Authorization: Bearer access token"]
    B -- 是 --> C{"refresh token 仍有效？"}
    C -- 是 --> D["POST /auth/refresh"]
    C -- 否 --> L["用 Basic 认证 POST /auth/token"]
    D -- "200" --> U
    D -- "401" --> L
    D -- "其他错误" --> K{"access token 仍有效？"}
    L -- "200" --> U
    L -- "错误" --> K
    K -- 是 --> R["继续使用，5 秒后再尝试续期"]
    R --> U
    K -- 否 --> X["该隧道请求失败"]
    U --> W["与 gateway 进行 WebSocket 握手"]
    W -- "101" --> OK["隧道建立"]
    W -- "401，第一次" --> M["标记该 token 被拒绝"]
    M --> A
```

token 不会写入日志，`Authorization` 头的值也被标记为敏感。

## 上游代理

`Settings::upstream_proxy` 会让所有出口连接经过一个代理服务器：访问 gateway 的连接（隧道、
健康检查和 token 请求）、被路由规则判定为直连的请求，以及规则列表的下载。用
`UpstreamProxy::parse` 解析，支持 `http://`（HTTP 代理，使用 `CONNECT`）、`socks5h://`（由代理
解析域名）和 `socks5://`（在本地解析域名）URL，可带 `user:pass@` 认证信息。设置后不会读取代理
环境变量。日志和错误信息只显示代理地址，不显示认证信息。

## 许可证

MIT。见 [`LICENSE`](LICENSE)。
