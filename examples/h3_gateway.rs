//! A minimal test gateway that speaks WebSocket over HTTP/3 (RFC 9220), for trying the
//! `http3` setting without a real gateway: `/tcp:host:port` tunnels to that TCP target.
//! It has a throwaway self-signed certificate (connect with `--insecure`), and no authentication.
//!
//! `cargo run --example h3_gateway -- 127.0.0.1:8443`

use std::{net::SocketAddr, sync::Arc};

use bytes::{Buf, Bytes};
use futures_util::{SinkExt, StreamExt};
use hpx_h3::{quinn as h3_quinn, server};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, duplex},
    net::TcpStream,
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message, http::Response, protocol::Role},
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let listen: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8443".to_owned())
        .parse()?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der())
                .map_err(anyhow::Error::msg)?,
        )?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let endpoint =
        quinn::Endpoint::server(quinn::ServerConfig::with_crypto(Arc::new(quic)), listen)?;
    eprintln!("h3 gateway listening on udp://{}", endpoint.local_addr()?);

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            if let Err(err) = serve_connection(incoming).await {
                eprintln!("connection error: {err:#}");
            }
        });
    }
    Ok(())
}

async fn serve_connection(incoming: quinn::Incoming) -> anyhow::Result<()> {
    let connection = incoming.await?;
    let mut h3 = server::builder()
        .enable_extended_connect(true)
        .build(h3_quinn::Connection::new(connection))
        .await?;
    while let Some(resolver) = h3.accept().await? {
        tokio::spawn(async move {
            if let Err(err) = serve_request(resolver).await {
                eprintln!("request error: {err:#}");
            }
        });
    }
    Ok(())
}

async fn serve_request(
    resolver: server::RequestResolver<h3_quinn::Connection, Bytes>,
) -> anyhow::Result<()> {
    let (request, mut stream) = resolver.resolve_request().await?;
    let target = request
        .uri()
        .path()
        .strip_prefix("/tcp:")
        .map(str::to_owned);
    let websocket = request.extensions().get::<hpx_h3::ext::Protocol>().copied()
        == Some(hpx_h3::ext::Protocol::WEBSOCKET);
    let Some(target) = target.filter(|_| websocket) else {
        stream
            .send_response(Response::builder().status(404).body(())?)
            .await?;
        return Ok(stream.finish().await?);
    };
    eprintln!("tunnel to {target}");
    let upstream = match TcpStream::connect(&target).await {
        Ok(upstream) => upstream,
        Err(err) => {
            stream
                .send_response(Response::builder().status(502).body(())?)
                .await?;
            eprintln!("cannot reach {target}: {err}");
            return Ok(stream.finish().await?);
        }
    };
    stream
        .send_response(Response::builder().status(200).body(())?)
        .await?;

    let (mut send, mut recv) = stream.split();
    let (websocket_side, pump_side) = duplex(64 * 1024);
    let (mut from_websocket, mut to_websocket) = tokio::io::split(pump_side);
    tokio::spawn(async move {
        while let Ok(Some(mut data)) = recv.recv_data().await {
            while data.has_remaining() {
                let len = data.chunk().len();
                if to_websocket.write_all(data.chunk()).await.is_err() {
                    return;
                }
                data.advance(len);
            }
        }
        let _ = to_websocket.shutdown().await;
    });
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 16 * 1024];
        while let Ok(n) = from_websocket.read(&mut buffer).await {
            if n == 0
                || send
                    .send_data(Bytes::copy_from_slice(&buffer[..n]))
                    .await
                    .is_err()
            {
                break;
            }
        }
        let _ = send.finish().await;
    });

    let websocket = WebSocketStream::from_raw_socket(websocket_side, Role::Server, None).await;
    let (mut ws_tx, mut ws_rx) = websocket.split();
    let (mut tcp_rx, mut tcp_tx) = upstream.into_split();
    let to_target = async {
        while let Some(Ok(message)) = ws_rx.next().await {
            match message {
                Message::Binary(bytes) => tcp_tx.write_all(&bytes).await?,
                Message::Close(_) => break,
                _ => {}
            }
        }
        tcp_tx.shutdown().await
    };
    let from_target = async {
        let mut buffer = vec![0_u8; 16 * 1024];
        loop {
            let n = tcp_rx.read(&mut buffer).await?;
            if n == 0 {
                let _ = ws_tx.send(Message::Close(None)).await;
                return std::io::Result::Ok(());
            }
            if ws_tx
                .send(Message::Binary(buffer[..n].to_vec().into()))
                .await
                .is_err()
            {
                return Ok(());
            }
        }
    };
    let _ = tokio::join!(to_target, from_target);
    Ok(())
}
