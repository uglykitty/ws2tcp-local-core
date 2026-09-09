use anyhow::{Context, Result, bail};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const SOCKS5_VERSION: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const AUTH_NO_AUTH: u8 = 0x00;
const AUTH_NO_ACCEPTABLE: u8 = 0xFF;

/// A SOCKS5 CONNECT reply reporting success, with an all-zero BND.ADDR/BND.PORT.
/// Clients are expected to use the tunnel itself rather than the bound address.
pub(crate) const SUCCESS_REPLY: [u8; 10] =
    [SOCKS5_VERSION, 0x00, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
/// A SOCKS5 CONNECT reply reporting a general server failure (REP 0x01).
pub(crate) const GENERAL_FAILURE_REPLY: [u8; 10] =
    [SOCKS5_VERSION, 0x01, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Socks5Request {
    pub(crate) authority: String,
}

/// Reads a SOCKS5 no-authentication handshake followed by a CONNECT request.
/// `socks5h` semantics fall out naturally: a domain-name (ATYP 0x03) target is
/// forwarded to the caller as a hostname rather than resolved locally here.
pub(crate) async fn read_socks5_request(client: &mut TcpStream) -> Result<Socks5Request> {
    negotiate_auth(client).await?;
    read_connect_request(client).await
}

async fn negotiate_auth(client: &mut TcpStream) -> Result<()> {
    let mut header = [0_u8; 2];
    client
        .read_exact(&mut header)
        .await
        .context("read SOCKS5 greeting failed")?;
    let [version, method_count] = header;
    if version != SOCKS5_VERSION {
        bail!("unsupported SOCKS version {version} in greeting");
    }

    let mut methods = vec![0_u8; method_count as usize];
    client
        .read_exact(&mut methods)
        .await
        .context("read SOCKS5 auth methods failed")?;

    if !methods.contains(&AUTH_NO_AUTH) {
        client
            .write_all(&[SOCKS5_VERSION, AUTH_NO_ACCEPTABLE])
            .await
            .context("write SOCKS5 method rejection failed")?;
        bail!(
            "client did not offer a supported SOCKS5 auth method; only no-authentication is supported"
        );
    }

    client
        .write_all(&[SOCKS5_VERSION, AUTH_NO_AUTH])
        .await
        .context("write SOCKS5 method selection failed")
}

async fn read_connect_request(client: &mut TcpStream) -> Result<Socks5Request> {
    let mut header = [0_u8; 4];
    client
        .read_exact(&mut header)
        .await
        .context("read SOCKS5 request header failed")?;
    let [version, cmd, _reserved, address_type] = header;
    if version != SOCKS5_VERSION {
        bail!("unsupported SOCKS version {version} in request");
    }
    if cmd != CMD_CONNECT {
        bail!("unsupported SOCKS5 command {cmd}; only CONNECT is supported");
    }

    let host = read_address(client, address_type).await?;
    let mut port = [0_u8; 2];
    client
        .read_exact(&mut port)
        .await
        .context("read SOCKS5 port failed")?;

    Ok(Socks5Request {
        authority: format!("{host}:{}", u16::from_be_bytes(port)),
    })
}

async fn read_address(client: &mut TcpStream, address_type: u8) -> Result<String> {
    match address_type {
        ATYP_IPV4 => {
            let mut octets = [0_u8; 4];
            client
                .read_exact(&mut octets)
                .await
                .context("read SOCKS5 IPv4 address failed")?;
            Ok(std::net::Ipv4Addr::from(octets).to_string())
        }
        ATYP_DOMAIN => {
            let mut len = [0_u8; 1];
            client
                .read_exact(&mut len)
                .await
                .context("read SOCKS5 domain length failed")?;
            let mut domain = vec![0_u8; len[0] as usize];
            client
                .read_exact(&mut domain)
                .await
                .context("read SOCKS5 domain name failed")?;
            String::from_utf8(domain).context("SOCKS5 domain name is not valid UTF-8")
        }
        ATYP_IPV6 => {
            let mut octets = [0_u8; 16];
            client
                .read_exact(&mut octets)
                .await
                .context("read SOCKS5 IPv6 address failed")?;
            Ok(format!("[{}]", std::net::Ipv6Addr::from(octets)))
        }
        other => bail!("unsupported SOCKS5 address type {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn parses_domain_connect_request() {
        let (mut client, mut server) = connected_pair().await;

        let write_task = tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut method_reply = [0_u8; 2];
            client.read_exact(&mut method_reply).await.unwrap();
            assert_eq!(method_reply, [0x05, 0x00]);

            let domain = b"example.com";
            let mut request = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
            request.extend_from_slice(domain);
            request.extend_from_slice(&443_u16.to_be_bytes());
            client.write_all(&request).await.unwrap();
        });

        let request = read_socks5_request(&mut server).await.unwrap();
        write_task.await.unwrap();

        assert_eq!(
            request,
            Socks5Request {
                authority: "example.com:443".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn parses_ipv4_connect_request() {
        let (mut client, mut server) = connected_pair().await;

        let write_task = tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut method_reply = [0_u8; 2];
            client.read_exact(&mut method_reply).await.unwrap();

            let mut request = vec![0x05, 0x01, 0x00, 0x01];
            request.extend_from_slice(&[127, 0, 0, 1]);
            request.extend_from_slice(&8080_u16.to_be_bytes());
            client.write_all(&request).await.unwrap();
        });

        let request = read_socks5_request(&mut server).await.unwrap();
        write_task.await.unwrap();

        assert_eq!(request.authority, "127.0.0.1:8080");
    }

    #[tokio::test]
    async fn parses_ipv6_connect_request() {
        let (mut client, mut server) = connected_pair().await;

        let write_task = tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut method_reply = [0_u8; 2];
            client.read_exact(&mut method_reply).await.unwrap();

            let mut request = vec![0x05, 0x01, 0x00, 0x04];
            request.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
            request.extend_from_slice(&443_u16.to_be_bytes());
            client.write_all(&request).await.unwrap();
        });

        let request = read_socks5_request(&mut server).await.unwrap();
        write_task.await.unwrap();

        assert_eq!(request.authority, "[::1]:443");
    }

    #[tokio::test]
    async fn rejects_unsupported_auth_method() {
        let (mut client, mut server) = connected_pair().await;

        let write_task = tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
            let mut method_reply = [0_u8; 2];
            client.read_exact(&mut method_reply).await.unwrap();
            assert_eq!(method_reply, [0x05, 0xFF]);
        });

        assert!(read_socks5_request(&mut server).await.is_err());
        write_task.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_unsupported_command() {
        let (mut client, mut server) = connected_pair().await;

        let write_task = tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut method_reply = [0_u8; 2];
            client.read_exact(&mut method_reply).await.unwrap();

            // BIND instead of CONNECT.
            let mut request = vec![0x05, 0x02, 0x00, 0x01];
            request.extend_from_slice(&[127, 0, 0, 1]);
            request.extend_from_slice(&8080_u16.to_be_bytes());
            client.write_all(&request).await.unwrap();
        });

        assert!(read_socks5_request(&mut server).await.is_err());
        write_task.await.unwrap();
    }
}
